"""
src/engine/nids_config.py
==========================
Pickle-compatibility shim for NIDSConfig.

WHY THIS EXISTS
───────────────
NIDSConfig is defined inside the training notebook's Cell 1. Its docstring
claims to be "module-level — pickle-safe", but module level *inside a
notebook* is still `__main__`, so pickle records the class path as
`__main__.NIDSConfig`. Unpickling anywhere other than that same notebook
kernel then fails with:

    AttributeError: Can't get attribute 'NIDSConfig' on
    <module '__main__' from '.../run_track_a.py'>

save_nids_output() sidesteps this by excluding `config` from what it writes,
so `nids_*_output.pkl` files are clean. But a raw `joblib.dump(results_x, ...)`
— as in the commented-out one-liners in notebook cells 5/7/9 — keeps the
config object and produces a pkl that only that notebook can read.

Rather than make those files unloadable, install_pickle_shims() registers a
stand-in class into `__main__` so the attribute resolves. The config is not
used by any evaluation code; it only has to survive being reconstructed.

The real fix is to import NIDSConfig from this module inside the notebook so
future pickles record a portable path — see the note at the bottom.
"""

import sys


class NIDSConfig:
    """Attribute bag matching the notebook's NIDSConfig.

    The notebook defines `class NIDSConfig: pass` and assigns attributes onto
    instances afterwards, so an empty class with permissive unpickling is a
    faithful stand-in. __setstate__ is defined explicitly because the notebook
    class has no __reduce__/__getstate__ and pickle restores it via __dict__.
    """

    def __setstate__(self, state):
        if isinstance(state, dict):
            self.__dict__.update(state)

    def __repr__(self):
        ds = getattr(self, "DATASET", "?")
        return f"<NIDSConfig dataset={ds} (compat shim)>"


def install_pickle_shims(verbose: bool = True) -> None:
    """Register notebook-local classes into __main__ so old pickles load.

    Call this BEFORE joblib.load() on any file produced by dumping a raw
    run_nids() result dict. It is a no-op when __main__ already provides the
    name, so it is safe to call unconditionally.
    """
    main_mod = sys.modules.get("__main__")
    if main_mod is None:
        return

    installed = []
    if not hasattr(main_mod, "NIDSConfig"):
        main_mod.NIDSConfig = NIDSConfig
        installed.append("NIDSConfig")

    # The same trap applies to these two if a pkl predates their move into
    # src/engine/. Point __main__ at the real classes, not stand-ins, so a
    # recovered object still behaves correctly.
    try:
        from src.engine.universal_ensemble import UniversalEnsemble
        if not hasattr(main_mod, "UniversalEnsemble"):
            main_mod.UniversalEnsemble = UniversalEnsemble
            installed.append("UniversalEnsemble")
    except ImportError:
        pass

    try:
        from src.engine.weighted_hybrid import WeightedHybridEnsemble
        if not hasattr(main_mod, "WeightedHybridEnsemble"):
            main_mod.WeightedHybridEnsemble = WeightedHybridEnsemble
            installed.append("WeightedHybridEnsemble")
    except ImportError:
        pass

    if installed and verbose:
        print(f"  (pickle compat: registered {', '.join(installed)} into __main__)")


# ─────────────────────────────────────────────────────────────────────────────
# PERMANENT FIX (do this once, then this shim stops mattering)
#
# In notebook Cell 1, replace:
#
#     class NIDSConfig:
#         """Module-level config class — pickle-safe ..."""
#         pass
#
# with:
#
#     from src.engine.nids_config import NIDSConfig
#
# Pickles written afterwards record `src.engine.nids_config.NIDSConfig` and
# load anywhere the project is importable — the same treatment already applied
# to UniversalEnsemble and WeightedHybridEnsemble.
# ─────────────────────────────────────────────────────────────────────────────
