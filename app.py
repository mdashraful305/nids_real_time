from flask import Flask, jsonify, render_template_string
import json
import os
from pathlib import Path

app = Flask(__name__)

ROOT_DIR = Path(__file__).resolve().parent
JSONL_FILE = os.environ.get(
    "UNIFIED_ALERTS_FILE",
    str(ROOT_DIR / "data" / "results" / "unified_alerts.jsonl"),
)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NIDS Unified SOC Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
    --bg-dark: #030712;
    --bg-card: rgba(15, 23, 42, 0.65);
    --border-color: rgba(255, 255, 255, 0.08);
    --border-glow: rgba(99, 102, 241, 0.15);
    
    --text-primary: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    
    --accent: #6366f1;
    --accent-glow: rgba(99, 102, 241, 0.35);
    
    /* Severity Colors */
    --sev-critical: #ef4444;
    --sev-critical-bg: rgba(239, 68, 68, 0.15);
    --sev-high: #f97316;
    --sev-high-bg: rgba(249, 115, 22, 0.15);
    --sev-medium: #eab308;
    --sev-medium-bg: rgba(234, 179, 8, 0.15);
    --sev-low: #10b981;
    --sev-low-bg: rgba(16, 185, 129, 0.15);
    --sev-none: #64748b;
    --sev-none-bg: rgba(100, 116, 139, 0.15);
    --sev-pending: #f59e0b;
    --sev-pending-bg: rgba(245, 158, 11, 0.12);
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    background: var(--bg-dark);
    background-image: radial-gradient(circle at 50% 0%, #1e1b4b 0%, var(--bg-dark) 70%);
    color: var(--text-primary);
    font-family: 'Outfit', sans-serif;
    height: 100vh;
    overflow: hidden;
    display: flex;
    flex-direction: column;
}

/* Scrollbars */
::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}
::-webkit-scrollbar-track {
    background: rgba(0, 0, 0, 0.2);
}
::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, 0.1);
    border-radius: 3px;
}
::-webkit-scrollbar-thumb:hover {
    background: rgba(255, 255, 255, 0.2);
}

/* Header */
.header {
    height: 64px;
    background: rgba(3, 7, 18, 0.8);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border-color);
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0 24px;
    z-index: 10;
}

.logo-section {
    display: flex;
    align-items: center;
    gap: 12px;
}

.logo-icon {
    font-size: 24px;
    filter: drop-shadow(0 0 8px var(--accent-glow));
}

.logo-text {
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 700;
    font-size: 20px;
    letter-spacing: 0.5px;
    background: linear-gradient(to right, #ffffff, #a5b4fc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.status-badge {
    display: flex;
    align-items: center;
    gap: 8px;
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.2);
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 13px;
    font-weight: 600;
    color: #34d399;
}

.status-dot {
    width: 8px;
    height: 8px;
    background: #10b981;
    border-radius: 50%;
    box-shadow: 0 0 12px #10b981;
    animation: pulse 1.8s infinite;
}

@keyframes pulse {
    0% { transform: scale(0.9); opacity: 0.6; box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
    70% { transform: scale(1.1); opacity: 1; box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
    100% { transform: scale(0.9); opacity: 0.6; box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}

/* Stats Summary */
.stats-container {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 16px;
    padding: 16px 24px 8px 24px;
}

.stat-card {
    background: var(--bg-card);
    backdrop-filter: blur(8px);
    border: 1px solid var(--border-color);
    border-radius: 14px;
    padding: 16px 20px;
    position: relative;
    overflow: hidden;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.stat-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: radial-gradient(circle at 0% 0%, var(--border-glow), transparent 60%);
    opacity: 0;
    transition: opacity 0.3s ease;
}

.stat-card:hover {
    transform: translateY(-2px);
    border-color: rgba(99, 102, 241, 0.3);
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
}

.stat-card:hover::before {
    opacity: 1;
}

.stat-label {
    color: var(--text-secondary);
    font-size: 13px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.stat-value {
    font-size: 32px;
    font-weight: 700;
    margin-top: 8px;
    font-family: 'Space Grotesk', sans-serif;
}

#highCount { color: var(--sev-high); }
#attackCount { color: var(--sev-critical); }
#benignCount { color: var(--sev-low); }

/* Main Dashboard Grid */
.dashboard-grid {
    flex: 1;
    display: grid;
    grid-template-columns: 380px 1fr 340px;
    gap: 20px;
    padding: 8px 24px 24px 24px;
    min-height: 0;
}

.grid-panel {
    background: var(--bg-card);
    backdrop-filter: blur(8px);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
}

.panel-title {
    padding: 18px 20px;
    border-bottom: 1px solid var(--border-color);
    font-weight: 600;
    font-size: 16px;
    letter-spacing: 0.3px;
    font-family: 'Space Grotesk', sans-serif;
    display: flex;
    justify-content: space-between;
    align-items: center;
}

/* Incident Queue */
.search-filter-box {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    flex-direction: column;
    gap: 10px;
}

.search-input {
    width: 100%;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border-color);
    padding: 10px 14px;
    border-radius: 8px;
    color: var(--text-primary);
    font-family: inherit;
    font-size: 14px;
    outline: none;
    transition: border-color 0.2s;
}

.search-input:focus {
    border-color: var(--accent);
}

.filter-btn-group {
    display: flex;
    gap: 8px;
    overflow-x: auto;
    padding-bottom: 4px;
}

.filter-btn {
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid var(--border-color);
    padding: 6px 12px;
    border-radius: 6px;
    color: var(--text-secondary);
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    transition: all 0.2s;
}

.filter-btn:hover {
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-primary);
}

.filter-btn.active {
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
    box-shadow: 0 0 10px rgba(99, 102, 241, 0.3);
}

.incident-feed {
    flex: 1;
    overflow-y: auto;
    padding: 10px;
}

.incident-card {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 14px;
    margin-bottom: 10px;
    cursor: pointer;
    position: relative;
    transition: all 0.25s ease;
}

.incident-card::before {
    content: '';
    position: absolute;
    left: 0;
    top: 12px;
    bottom: 12px;
    width: 4px;
    border-radius: 0 4px 4px 0;
}

.incident-card:hover {
    transform: translateX(4px);
    background: rgba(255, 255, 255, 0.04);
    border-color: rgba(255, 255, 255, 0.15);
}

.incident-card.active {
    background: rgba(99, 102, 241, 0.08);
    border-color: var(--accent);
    box-shadow: 0 0 15px rgba(99, 102, 241, 0.1) inset;
}

.incident-card.critical::before { background: var(--sev-critical); }
.incident-card.high::before { background: var(--sev-high); }
.incident-card.medium::before { background: var(--sev-medium); }
.incident-card.low::before { background: var(--sev-low); }
.incident-card.none::before { background: var(--sev-none); }

.card-header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}

.severity-tag {
    font-size: 11px;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
    text-transform: uppercase;
}

.critical .severity-tag { background: var(--sev-critical-bg); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
.high .severity-tag { background: var(--sev-high-bg); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
.medium .severity-tag { background: var(--sev-medium-bg); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
.low .severity-tag { background: var(--sev-low-bg); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
.none .severity-tag { background: var(--sev-none-bg); color: #94a3b8; border: 1px solid rgba(100, 116, 139, 0.3); }

.card-time {
    font-size: 12px;
    color: var(--text-muted);
}

.card-title-text {
    font-weight: 600;
    font-size: 15px;
    margin-bottom: 6px;
}

.card-verdict-row {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    color: var(--text-secondary);
}

/* Investigation Details Panel */
.investigation-area {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
}

.investigation-empty {
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    color: var(--text-muted);
    gap: 16px;
}

.empty-icon {
    font-size: 48px;
    opacity: 0.5;
}

.details-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
    margin-bottom: 24px;
}

.detail-item {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 14px;
}

.item-label {
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
}

.item-value {
    font-size: 16px;
    font-weight: 600;
}

/* Key Indicators & Chips */
.indicator-section {
    margin-bottom: 24px;
}

.chip-container {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 8px;
}

.indicator-chip {
    background: rgba(99, 102, 241, 0.1);
    border: 1px solid rgba(99, 102, 241, 0.2);
    color: #a5b4fc;
    padding: 6px 12px;
    border-radius: 8px;
    font-size: 13px;
    font-family: 'JetBrains Mono', monospace;
}

/* Consensus Component */
.consensus-box {
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 16px;
    margin-bottom: 24px;
}

.consensus-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 12px;
    font-weight: 600;
    font-size: 14px;
}

.status-pill {
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
}

.status-pill.agreed { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.2); }
.status-pill.conflict { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.2); }

.role-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
}

.role-card {
    background: rgba(0, 0, 0, 0.2);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 12px;
}

.role-name {
    font-size: 11px;
    color: var(--text-muted);
    font-weight: 600;
    margin-bottom: 4px;
}

.role-verdict {
    font-size: 14px;
    font-weight: 700;
}

/* Explanation Card */
.expl-box {
    background: rgba(255, 255, 255, 0.02);
    border-left: 3px solid var(--accent);
    border-radius: 4px 12px 12px 4px;
    padding: 16px;
    line-height: 1.6;
    font-size: 14px;
    color: var(--text-primary);
    margin-bottom: 24px;
}

/* Action Box */
.action-card {
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(16, 185, 129, 0.03) 100%);
    border: 1px solid rgba(99, 102, 241, 0.25);
    border-radius: 12px;
    padding: 18px;
    margin-bottom: 24px;
}

.action-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 700;
    font-size: 14px;
    color: #a5b4fc;
    margin-bottom: 8px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.action-content {
    font-size: 14px;
    line-height: 1.5;
}

/* Raw Toggle Controls */
.json-toggle-btn {
    width: 100%;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid var(--border-color);
    color: var(--text-secondary);
    padding: 12px;
    border-radius: 10px;
    cursor: pointer;
    font-weight: 600;
    font-size: 13px;
    transition: all 0.2s;
    margin-top: 10px;
}

.json-toggle-btn:hover {
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-primary);
}

.raw-json-block {
    display: none;
    background: rgba(0, 0, 0, 0.4);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 16px;
    margin-top: 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    overflow-x: auto;
    color: #38bdf8;
    max-height: 300px;
}

/* Right Panel: Analytics & Threat Metrics */
.analytics-section {
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    overflow-y: auto;
    height: 100%;
}

.metric-row {
    background: rgba(255, 255, 255, 0.01);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 16px;
}

.metric-head {
    display: flex;
    justify-content: space-between;
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 8px;
}

.metric-num {
    font-size: 24px;
    font-weight: 700;
    font-family: 'Space Grotesk', sans-serif;
}

.confidence-bar-bg {
    width: 100%;
    height: 6px;
    background: rgba(255, 255, 255, 0.05);
    border-radius: 3px;
    overflow: hidden;
}

.confidence-bar-fill {
    height: 100%;
    background: linear-gradient(to right, var(--accent), #10b981);
    width: 0%;
    transition: width 0.8s ease;
}

/* LLM Pending badge */
.llm-pending-badge {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    background: var(--sev-pending-bg);
    border: 1px solid rgba(245, 158, 11, 0.3);
    color: #fbbf24;
    font-size: 10px;
    font-weight: 700;
    padding: 2px 7px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.4px;
}

.llm-pending-dot {
    width: 6px;
    height: 6px;
    background: #f59e0b;
    border-radius: 50%;
    animation: llmPulse 1.2s ease-in-out infinite;
}

@keyframes llmPulse {
    0%, 100% { opacity: 0.4; transform: scale(0.8); }
    50% { opacity: 1; transform: scale(1.2); box-shadow: 0 0 6px #f59e0b; }
}

.llm-pending-strip {
    background: linear-gradient(90deg,
        rgba(245,158,11,0.06) 0%,
        rgba(245,158,11,0.12) 50%,
        rgba(245,158,11,0.06) 100%);
    border: 1px solid rgba(245, 158, 11, 0.2);
    border-radius: 10px;
    padding: 12px 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
    font-size: 13px;
    color: #fbbf24;
}

.llm-spinner {
    width: 16px;
    height: 16px;
    border: 2px solid rgba(245,158,11,0.2);
    border-top-color: #f59e0b;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    flex-shrink: 0;
}

@keyframes spin {
    to { transform: rotate(360deg); }
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateY(6px); }
    to   { opacity: 1; transform: translateY(0); }
}

</style>
</head>
<body>

<header class="header">
    <div class="logo-section">
        <span class="logo-icon">🛡️</span>
        <span class="logo-text">CYBER NIDS // SOC CORE</span>
    </div>
    <div class="status-badge">
        <div class="status-dot"></div>
        <span>LIVE PIPELINE ACTIVE</span>
    </div>
</header>

<section class="stats-container">
    <div class="stat-card">
        <div class="stat-label">Total Signals</div>
        <div class="stat-value" id="totalAlerts">0</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Active Attacks</div>
        <div class="stat-value" id="attackCount">0</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Benign Traffic</div>
        <div class="stat-value" id="benignCount">0</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Escalations</div>
        <div class="stat-value" id="highCount">0</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Telemetry Age</div>
        <div class="stat-value" id="lastUpdate">--</div>
    </div>
</section>

<main class="dashboard-grid">
    <!-- Left Panel: Incident Queue -->
    <div class="grid-panel">
        <div class="panel-title">
            <span>Incident Queue</span>
        </div>
        <div class="search-filter-box">
            <input type="text" id="searchInput" class="search-input" placeholder="Search by signature, protocol, IP..." oninput="applyFilters()">
            <div class="filter-btn-group">
                <button class="filter-btn active" onclick="setSeverityFilter('ALL')">ALL</button>
                <button class="filter-btn" onclick="setSeverityFilter('HIGH')">HIGH</button>
                <button class="filter-btn" onclick="setSeverityFilter('MEDIUM')">MEDIUM</button>
                <button class="filter-btn" onclick="setSeverityFilter('LOW')">LOW</button>
                <button class="filter-btn" onclick="setSeverityFilter('NONE')">SUPPRESSED</button>
            </div>
        </div>
        <div class="incident-feed" id="alertFeed"></div>
    </div>

    <!-- Center Panel: Investigation Core -->
    <div class="grid-panel">
        <div class="panel-title">Signal Investigation Panel</div>
        <div class="investigation-area" id="details">
            <div class="investigation-empty">
                <div class="empty-icon">🔍</div>
                <h3>Awaiting Alert Selection</h3>
                <p style="color:var(--text-muted); font-size:14px;">Select an alert from the incident queue to inspect telemetry data</p>
            </div>
        </div>
    </div>

    <!-- Right Panel: Analytics & Threat Metrics -->
    <div class="grid-panel">
        <div class="panel-title">Threat Analytics</div>
        <div class="analytics-section">
            <div class="metric-row">
                <div class="metric-head">
                    <span>Average System Confidence</span>
                </div>
                <div class="metric-num" id="avgConfidence">0%</div>
                <div class="confidence-bar-bg" style="margin-top:10px;">
                    <div class="confidence-bar-fill" id="confidenceBar"></div>
                </div>
            </div>

            <div class="metric-row">
                <div class="metric-head">
                    <span>DoS Detections</span>
                </div>
                <div class="metric-num" id="dosCount">0</div>
            </div>

            <div class="metric-row">
                <div class="metric-head">
                    <span>Suppressed Noise Logs</span>
                </div>
                <div class="metric-num" id="suppressedCount">0</div>
            </div>

            <div class="metric-row">
                <div class="metric-head">
                    <span>Active Conflicts</span>
                </div>
                <div class="metric-num" id="conflictCount">0</div>
            </div>
        </div>
    </div>
</main>

<script>
let allAlerts = [];
let alertsById = {};
let severityFilter = 'ALL';
let currentSelectedId = null;

function setSeverityFilter(sev) {
    severityFilter = sev;
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.innerText === sev || (sev === 'NONE' && btn.innerText === 'SUPPRESSED')) {
            btn.classList.add('active');
        }
    });
    applyFilters();
}

function applyFilters() {
    const searchVal = document.getElementById("searchInput").value.toLowerCase();
    const feed = document.getElementById("alertFeed");
    feed.innerHTML = "";

    const filtered = allAlerts.filter(alert => {
        // Severity Filter
        const matchesSeverity = (severityFilter === 'ALL') || 
                                (alert.severity === severityFilter);
        
        // Search Filter
        const matchesSearch = !searchVal || 
                              alert.attack_type.toLowerCase().includes(searchVal) ||
                              (alert.severity && alert.severity.toLowerCase().includes(searchVal)) ||
                              (alert.final_verdict && alert.final_verdict.toLowerCase().includes(searchVal)) ||
                              (alert.key_indicators && alert.key_indicators.some(i => i.toLowerCase().includes(searchVal))) ||
                              // FIX: src_ip/dst_ip are written under
                              // alert.flow_features, not at the top level —
                              // reading alert.src_ip directly always
                              // resolves to undefined, which is why every
                              // alert showed "unknown:--" for Source/
                              // Destination regardless of whether real flow
                              // data existed for it.
                              (alert.flow_features?.src_ip && alert.flow_features.src_ip.toLowerCase().includes(searchVal)) ||
                              (alert.flow_features?.dst_ip && alert.flow_features.dst_ip.toLowerCase().includes(searchVal)) ||
                              (alert.soc_explanation && alert.soc_explanation.toLowerCase().includes(searchVal));
                              
        return matchesSeverity && matchesSearch;
    });

    if (filtered.length === 0) {
        feed.innerHTML = `<div style="text-align:center; padding:40px 20px; color:var(--text-muted);">No incidents match filters</div>`;
        return;
    }

    alertsById = {};
    filtered.forEach((alert, idx) => {
        const sev = (alert.severity || "NONE").toLowerCase();
        const isPending = (alert.llm_enriched === false || alert.role3_verdict === 'pending');
        const alertId = (alert.chunk_index !== undefined ? 'ci_' + alert.chunk_index : alert.timestamp + "_" + idx);
        const activeClass = (currentSelectedId === alertId) ? "active" : "";
        const pendingBadge = isPending
            ? `<span class="llm-pending-badge"><span class="llm-pending-dot"></span>LLM Pending</span>`
            : ``;
        alertsById[alertId] = alert;

        feed.innerHTML += `
            <div class="incident-card ${sev} ${activeClass}" id="card_${alertId}" onclick="selectAlertById('${alertId}')">
                <div class="card-header-row">
                    <span class="severity-tag">${alert.severity}</span>
                    <div style="display:flex;gap:6px;align-items:center;">
                        ${pendingBadge}
                        <span class="card-time">${new Date(alert.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'})}</span>
                    </div>
                </div>
                <div class="card-title-text">${alert.attack_type}</div>
                ${alert.flow_features?.src_ip ? `
                <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 8px; font-family: 'JetBrains Mono', monospace;">
                    ${alert.flow_features.src_ip} ➔ ${alert.flow_features.dst_ip}
                </div>
                ` : ''}
                <div class="card-verdict-row">
                    <span>R1: ${alert.role1_verdict || 'unknown'} · R3: ${isPending ? '⏳' : alert.role3_verdict || '?'}</span>
                    <span style="color: #60a5fa; font-weight:600;">${alert.confidence}% conf</span>
                </div>
            </div>
        `;
    });

    // Auto-select first item if details is empty and alerts are present
    if (filtered.length > 0 && !currentSelectedId) {
        const firstAlert = filtered[0];
        const firstId = (firstAlert.chunk_index !== undefined ? 'ci_' + firstAlert.chunk_index : firstAlert.timestamp + "_0");
        selectAlert(firstAlert, firstId);
    }
}

function selectAlertById(id) {
    const alert = alertsById[id];
    if (alert) selectAlert(alert, id);
}

function selectAlert(alert, id) {
    currentSelectedId = id;
    
    // Manage active state classes on cards
    document.querySelectorAll('.incident-card').forEach(card => {
        card.classList.remove('active');
    });
    const activeCard = document.getElementById('card_' + id);
    if (activeCard) activeCard.classList.add('active');

    const isPending = (alert.llm_enriched === false || alert.role3_verdict === 'pending');
    const consensusClass = alert.conflict ? "conflict" : "agreed";
    const consensusText = alert.conflict ? "Conflict Detected ⚠" : "Consensus Achieved ✓";
    const parsedTime = new Date(alert.timestamp).toLocaleString();

    const role3Block = isPending ? `
        <div class="role-card" style="border-color:rgba(245,158,11,0.3); background:rgba(245,158,11,0.04);">
            <div class="role-name" style="color:#fbbf24;">Role 3: LLM Analyst</div>
            <div class="role-verdict" style="display:flex;align-items:center;gap:8px;">
                <div class="llm-spinner"></div>
                <span style="color:#fbbf24;font-size:13px;">Processing…</span>
            </div>
            <div style="font-size:11px; color:var(--text-muted); margin-top:4px;">LLM enrichment in queue</div>
        </div>
    ` : `
        <div class="role-card">
            <div class="role-name">Role 3: LLM Analyst</div>
            <div class="role-verdict">${(alert.role3_verdict||'unknown').toUpperCase()}</div>
            <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">
                ${alert.role3_attack_type || "None"} (${alert.role3_confidence}% conf)
            </div>
        </div>
    `;

    const llmPendingStrip = isPending ? `
        <div class="llm-pending-strip">
            <div class="llm-spinner"></div>
            <div>
                <strong>LLM Analyst Running in Background</strong>
                <div style="font-size:12px;opacity:0.8;margin-top:2px;">Role 1 (ML) verdict is live. LLM explanation will appear here automatically in ~30s when ready.</div>
            </div>
        </div>
    ` : '';

    document.getElementById("details").innerHTML = `
        <div style="animation: fadeIn 0.3s ease;">
            <!-- LLM Pending Notice -->
            ${llmPendingStrip}

            <!-- Main Grid Indicators -->
            <div class="details-grid">
                <div class="detail-item">
                    <div class="item-label">Attack Signature</div>
                    <div class="item-value" style="color:var(--sev-critical);">${alert.attack_type}</div>
                </div>
                <div class="detail-item">
                    <div class="item-label">Incident Severity</div>
                    <div class="item-value" style="color: var(--sev-${alert.severity.toLowerCase()});">${alert.severity}</div>
                </div>
                <div class="detail-item">
                    <div class="item-label">Final Verdict</div>
                    <div class="item-value" style="text-transform: uppercase;">${alert.final_verdict}</div>
                </div>
                <div class="detail-item">
                    <div class="item-label">Evaluation Timestamp</div>
                    <div class="item-value" style="font-size:14px; font-weight:500;">${parsedTime}</div>
                </div>
            </div>

            <!-- Network Connection Telemetry -->
            <div class="consensus-box" style="margin-bottom: 24px;">
                <div class="consensus-header">
                    <span>Network Connection Telemetry</span>
                </div>
                <div style="display: grid; grid-template-columns: 2fr 2fr 1fr; gap: 12px; font-family: 'JetBrains Mono', monospace; font-size: 13px;">
                    <div class="role-card">
                        <div class="role-name">Source</div>
                        <div class="item-value" style="color: #60a5fa; font-size: 14px;">${alert.flow_features?.src_ip || 'unknown'}:${alert.flow_features?.src_port || '--'}</div>
                    </div>
                    <div class="role-card">
                        <div class="role-name">Destination</div>
                        <div class="item-value" style="color: #f87171; font-size: 14px;">${alert.flow_features?.dst_ip || 'unknown'}:${alert.flow_features?.dst_port || '--'}</div>
                    </div>
                    <div class="role-card">
                        <div class="role-name">Protocol</div>
                        <div class="item-value" style="color: #34d399; font-size: 14px;">${alert.flow_features?.protocol || 'TCP'}</div>
                    </div>
                </div>
            </div>

            <!-- Role consensus module -->
            <div class="consensus-box">
                <div class="consensus-header">
                    <span>Pipeline Alignment</span>
                    <span class="status-pill ${consensusClass}">${consensusText}</span>
                </div>
                <div class="role-grid">
                    <div class="role-card">
                        <div class="role-name">Role 1: ML Model ⚡</div>
                        <div class="role-verdict">${(alert.role1_verdict||'unknown').toUpperCase()}</div>
                        <div style="font-size:11px; color:var(--text-muted); margin-top:2px;">
                            ${alert.role1_attack_type} (${Math.round(alert.role1_confidence)}% conf)
                        </div>
                    </div>
                    ${role3Block}
                </div>
            </div>

            <!-- SHAP Explainability Section -->
            <div class="indicator-section">
                <div class="item-label">SHAP Feature Importance (Role 1)</div>
                <div class="chip-container" style="display:flex; flex-direction:column; gap:6px;">
                    ${(alert.shap_top_features && alert.shap_top_features.length > 0) 
                        ? alert.shap_top_features.map(f => {
                            let text = f;
                            let weightStr = f.match(/\\((.*?)\\)/);
                            let pct = 10;
                            if (weightStr) {
                                let w = parseFloat(weightStr[1]);
                                if (!isNaN(w)) pct = Math.max(5, Math.min(100, w * 100));
                            }
                            return `
                            <div style="display:flex; align-items:center; gap:10px; width:100%;">
                                <span class="indicator-chip" style="flex:1;">${text}</span>
                                <div style="width:100px; height:6px; background:rgba(255,255,255,0.05); border-radius:3px; overflow:hidden;">
                                    <div style="width:${pct}%; height:100%; background:var(--accent);"></div>
                                </div>
                            </div>`;
                        }).join('')
                        : '<span style="color:var(--text-muted); font-size:13px; font-style:italic;">No SHAP values available</span>'
                    }
                </div>
            </div>

            <!-- Key Indicators Section -->
            <div class="indicator-section">
                <div class="item-label">Key Telemetry Indicators</div>
                <div class="chip-container">
                    ${(alert.key_indicators || []).length > 0
                        ? (alert.key_indicators || []).map(ind => `<span class="indicator-chip">${ind}</span>`).join('')
                        : (isPending ? '<span style="color:var(--text-muted);font-size:13px;font-style:italic;">Awaiting LLM analysis…</span>' : '<span style="color:var(--text-muted);font-size:13px;">None</span>')
                    }
                </div>
            </div>

            <!-- SOC Log Explanation -->
            <div class="indicator-section">
                <div class="item-label">SOC Core Explanation</div>
                <div class="expl-box" style="${isPending ? 'border-left-color:#f59e0b;' : ''}">
                    ${isPending
                        ? `<span style="color:#fbbf24;">⏳ Role 1 ML Assessment:</span> ${alert.soc_explanation || 'Awaiting full analysis.'}<br><br><span style="color:var(--text-muted);font-size:12px;">LLM explanation will enrich this field automatically when processing completes.</span>`
                        : (alert.soc_explanation || "No explanation provided.")
                    }
                </div>
            </div>

            <!-- Recommended Mitigation Action -->
            <div class="action-card">
                <div class="action-title">
                    <span>🛡️ Recommended Action Plan</span>
                </div>
                <div class="action-content">
                    ${isPending
                        ? `<span style="color:var(--text-muted);">⏳ Awaiting LLM verdict…</span> ${alert.recommended_action || ''}`
                        : (alert.recommended_action || "Investigate telemetry logs manually.")
                    }
                </div>
            </div>

            <button class="json-toggle-btn" onclick="toggleRaw()">
                Toggle Raw Telemetry Payload
            </button>
            <pre class="raw-json-block" id="rawData">${JSON.stringify(alert, null, 2)}</pre>
        </div>
    `;
}

function toggleRaw() {
    const raw = document.getElementById("rawData");
    raw.style.display = (raw.style.display === "block") ? "none" : "block";
}

async function loadData() {
    try {
        const res = await fetch("/data");
        const alerts = await res.json();
        
        const prevAlerts = allAlerts;
        allAlerts = alerts.reverse(); // Newest first

        // Auto-refresh detail panel if selected alert got LLM enrichment
        if (currentSelectedId) {
            const updatedAlert = allAlerts.find(a => {
                const aid = (a.chunk_index !== undefined ? 'ci_' + a.chunk_index : a.timestamp + '_0');
                return aid === currentSelectedId;
            });
            if (updatedAlert && updatedAlert.llm_enriched === true) {
                // LLM just finished for the currently-viewed alert — refresh details
                selectAlert(updatedAlert, currentSelectedId);
            }
        }

        // Update stats cards
        document.getElementById("totalAlerts").innerText = allAlerts.length;
        document.getElementById("attackCount").innerText = allAlerts.filter(x => x.final_verdict === "attack").length;
        document.getElementById("benignCount").innerText = allAlerts.filter(x => x.final_verdict === "benign").length;
        document.getElementById("highCount").innerText = allAlerts.filter(x => x.severity === "HIGH").length;
        document.getElementById("lastUpdate").innerText = new Date().toLocaleTimeString();

        // Update Threat Analytics panel
        document.getElementById("suppressedCount").innerText = allAlerts.filter(x => x.suppressed).length;
        document.getElementById("dosCount").innerText = allAlerts.filter(x => x.attack_type === "DoS").length;
        document.getElementById("conflictCount").innerText = allAlerts.filter(x => x.conflict).length;

        // Calculate average confidence
        let avgConf = 0;
        if (allAlerts.length > 0) {
            avgConf = Math.round(allAlerts.reduce((a, b) => a + (b.confidence || 0), 0) / allAlerts.length);
        }
        document.getElementById("avgConfidence").innerText = avgConf + "%";
        document.getElementById("confidenceBar").style.width = avgConf + "%";

        // Refresh feed with filters applied
        applyFilters();
    } catch (err) {
        console.error("Failed loading alerts payload", err);
    }
}

// Initial pull & start polling
loadData();
setInterval(loadData, 2000);
</script>
</body>
</html>
"""

def read_jsonl():
    records = []

    path = Path(JSONL_FILE)

    if not path.exists():
        return []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                records.append(json.loads(line))
            except Exception:
                pass

    return records

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/data")
def data():
    return jsonify(read_jsonl())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5001")), debug=True)