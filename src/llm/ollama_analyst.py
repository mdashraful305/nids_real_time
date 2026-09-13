"""
src/llm/ollama_analyst.py
==========================
Send log chunks to a local Ollama LLM and parse structured JSON verdicts.

The LLM is prompted to act as a SOC analyst and return a JSON object with:
  verdict        : "attack" | "suspicious" | "benign"
  attack_type    : one of the known CICIDS2017 attack categories
  confidence     : 0-100
  key_indicators : list of specific feature/alert names that drove the verdict
  explanation    : 2-3 sentence plain-English explanation
  recommended_action : one concrete SOC action

Usage
-----
analyst = OllamaAnalyst(cfg)
verdict = analyst.analyse(chunk_text)
print(verdict["verdict"], verdict["explanation"])
"""

import json
import time
import re
from typing import Optional

import requests

from src.utils.logger import get_logger

log = get_logger(__name__)

# ── system prompt ─────────────────────────────────────────────────────────────
# Carefully engineered:
#   1. Clear role definition
#   2. Exactly what the chunk contains
#   3. Strict JSON-only output requirement
#   4. Concrete attack type vocabulary matching CICIDS2017 labels

SYSTEM_PROMPT = """You are a network security analyst.
Analyse the log window and respond with ONLY a JSON object, nothing else.
No markdown, no explanation before or after the JSON.

Required format:
{
  "verdict": "attack" or "suspicious" or "benign",
  "attack_type": "DoS" or "PortScan" or "Brute Force" or "Web Attack" or "Bot" or "DDoS" or "Normal" or "Unknown",
  "confidence": integer 0 to 100,
  "key_indicators": ["list", "of", "features"],
  "explanation": "one sentence explanation",
  "recommended_action": "one action"
}

Rules:
- If Suricata fired an alert, classify as attack or suspicious.
- If no alerts and traffic looks normal, classify as benign.
- Output ONLY the JSON. No other text."""

# SYSTEM_PROMPT = """Network security analyst. Respond ONLY with JSON, no other text.
# Required keys: verdict (attack/suspicious/benign), attack_type (DoS/DDoS/PortScan/Brute Force/Web Attack/Bot/Normal/Unknown), confidence (0-100), key_indicators (list of up to 3 strings), explanation (one sentence), recommended_action (one sentence).
# If Suricata alert fired → attack or suspicious. SYN flood pattern → DoS. Many ports → PortScan. Repeated auth failures → Brute Force."""

# ── default verdict returned on LLM failure ───────────────────────────────────
ERROR_VERDICT = {
    "verdict":            "error",
    "attack_type":        "Unknown",
    "confidence":         0,
    "key_indicators":     [],
    "explanation":        "LLM analysis failed — see logs for details.",
    "recommended_action": "Review raw logs manually.",
    "_error":             True,
}


class OllamaAnalyst:
    """
    Wraps the Ollama /api/generate endpoint and handles:
      - JSON extraction from LLM output (strips markdown fences if present)
      - Retry on timeout or connection error
      - Validation that all required keys are present
      - Fallback to ERROR_VERDICT if all retries fail

    Parameters
    ----------
    cfg : Config object (from config_loader.load_config())
    """

    REQUIRED_KEYS = {
        "verdict", "attack_type", "confidence",
        "key_indicators", "explanation", "recommended_action",
    }
    VALID_VERDICTS   = {"attack", "suspicious", "benign", "error"}
    VALID_ATTACK_TYPES = {
        "DoS", "DDoS", "PortScan", "Brute Force",
        "Web Attack", "Bot", "Infiltration", "Heartbleed",
        "FTP-Patator", "SSH-Patator", "Normal", "Unknown",
    }

    def __init__(self, cfg):
        self.url         = cfg.ollama.url
        self.model       = cfg.ollama.model
        self.temperature = cfg.ollama.temperature
        self.max_tokens  = cfg.ollama.max_tokens
        self.timeout     = cfg.ollama.timeout_seconds
        self.retries     = cfg.ollama.retry_attempts
        self.generate_ep = f"{self.url}/api/generate"

    # ── public ────────────────────────────────────────────────────────────────

    def check_connection(self) -> bool:
        """Return True if Ollama server is reachable and model is available."""
        try:
            r = requests.get(f"{self.url}/api/tags", timeout=5)
            if r.status_code != 200:
                log.error("Ollama /api/tags returned status %d", r.status_code)
                return False
            models = [m["name"] for m in r.json().get("models", [])]
            # Accept prefix match (e.g. "qwen2.5:7b" matches "qwen2.5:7b-instruct-q4")
            model_base = self.model.split(":")[0]
            matched = any(model_base in m for m in models)
            if not matched:
                log.warning(
                    "Model '%s' not found in Ollama. Available: %s",
                    self.model, models,
                )
            return matched
        except requests.exceptions.ConnectionError:
            log.error("Cannot connect to Ollama at %s", self.url)
            return False

    def analyse(self, chunk_text: str, chunk_index: int = 0) -> dict:
        """
        Send one log chunk to Ollama and return a structured verdict dict.

        Parameters
        ----------
        chunk_text  : str — text produced by format_chunk_text()
        chunk_index : int — used for logging only

        Returns
        -------
        dict with keys: verdict, attack_type, confidence, key_indicators,
                        explanation, recommended_action
                        (plus _error=True and _raw on failure)
        """
        last_error = None

        for attempt in range(1, self.retries + 1):
            try:
                log.debug(
                    "Sending chunk #%04d to Ollama (attempt %d/%d, model=%s)",
                    chunk_index, attempt, self.retries, self.model,
                )
                t0 = time.time()

                resp = requests.post(
                    self.generate_ep,
                    json={
                        "model":   self.model,
                        "system":  SYSTEM_PROMPT,
                        "prompt":  chunk_text,
                        "stream":  False,
                        "options": {
                            "temperature": self.temperature,
                            "num_predict": self.max_tokens,
                            "top_p":       0.9,
                            "repeat_penalty": 1.1,
                        },
                    },
                    timeout=self.timeout,
                )
                elapsed = time.time() - t0

                if resp.status_code != 200:
                    last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
                    log.warning("Ollama HTTP error: %s", last_error)
                    continue

                raw_text = resp.json().get("response", "").strip()
                log.debug(
                    "Chunk #%04d LLM response in %.1f s: %s...",
                    chunk_index, elapsed, raw_text[:80],
                )

                verdict = self._parse_verdict(raw_text, chunk_index)
                if verdict is not None:
                    verdict["_llm_seconds"] = round(elapsed, 2)
                    return verdict

                last_error = "Could not parse valid JSON from LLM response"

            except requests.exceptions.Timeout:
                last_error = f"Timeout after {self.timeout}s"
                log.warning("Chunk #%04d: %s (attempt %d)", chunk_index, last_error, attempt)
            except requests.exceptions.ConnectionError as exc:
                last_error = f"ConnectionError: {exc}"
                log.error("Ollama unreachable: %s", exc)
                break   # no point retrying if server is down
            except Exception as exc:
                last_error = str(exc)
                log.error("Unexpected error on chunk #%04d: %s", chunk_index, exc)

            if attempt < self.retries:
                time.sleep(2 * attempt)   # exponential back-off

        log.error(
            "All %d attempts failed for chunk #%04d: %s",
            self.retries, chunk_index, last_error,
        )
        result = dict(ERROR_VERDICT)
        result["_error_detail"] = last_error
        return result

    # ── internal ──────────────────────────────────────────────────────────────

    def _parse_verdict(self, raw: str, chunk_index: int) -> Optional[dict]:
        """
        Extract and validate JSON from the LLM's raw text output.
        Handles:
          - Clean JSON
          - JSON wrapped in ```json ... ``` markdown fences
          - JSON buried after preamble text
        """
        # 1. Strip markdown fences
        text = re.sub(r"```(?:json)?", "", raw, flags=re.IGNORECASE).strip()

        # 2. Try to find the outermost JSON object
        json_match = re.search(r"\{[\s\S]*\}", text)
        if not json_match:
            log.warning("No JSON object found in LLM output for chunk #%04d", chunk_index)
            log.debug("Raw output: %s", raw[:300])
            return None

        json_str = json_match.group(0)

        try:
            verdict = json.loads(json_str)
        except json.JSONDecodeError as exc:
            log.warning(
                "JSON parse error for chunk #%04d: %s — raw: %s",
                chunk_index, exc, json_str[:200],
            )
            return None

        # 3. Validate required keys
        missing = self.REQUIRED_KEYS - set(verdict.keys())
        if missing:
            log.warning(
                "LLM verdict missing keys %s for chunk #%04d", missing, chunk_index
            )
            # Fill in defaults for missing keys rather than failing
            verdict.setdefault("verdict", "suspicious")
            if not verdict.get("attack_type", "").strip():
                verdict["attack_type"] = "Unknown"
            verdict.setdefault("confidence", 50)
            verdict.setdefault("key_indicators", [])
            verdict.setdefault("explanation", "Partial LLM response.")
            verdict.setdefault("recommended_action", "Manual review recommended.")

        # 4. Normalise values
        verdict["verdict"] = str(verdict.get("verdict", "suspicious")).lower()
        if verdict["verdict"] not in self.VALID_VERDICTS:
            verdict["verdict"] = "suspicious"

        try:
            verdict["confidence"] = max(0, min(100, int(verdict["confidence"])))
        except (TypeError, ValueError):
            verdict["confidence"] = 50

        if not isinstance(verdict.get("key_indicators"), list):
            verdict["key_indicators"] = []

        return verdict
