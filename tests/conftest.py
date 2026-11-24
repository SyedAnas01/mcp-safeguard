"""Shared pytest fixtures.

`_isolate_tmd_cache` (autouse): `threat_model.py`'s TMD cache now lives in
a GLOBAL, user-owned directory (`~/.cache/mcp_safeguard/tmd/`, moved out
of the scanned target itself -- see `threat_model.py`'s own module
docstring "Security" note) rather than inside whichever repo a test
happens to be scanning. Without this fixture, any test that calls
`build_threat_model()`/`hunt()`/`hunt_fleet()` with caching enabled (the
default) would read and write the REAL developer machine's
`~/.cache/mcp_safeguard/tmd/` directory. This redirects that global
default to a fresh, per-test directory under `tmp_path` for every test in
the suite, so running the tests never touches the real user's home cache.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_tmd_cache(tmp_path, monkeypatch):
    from mcp_safeguard.scanner import threat_model as _threat_model_mod

    monkeypatch.setattr(_threat_model_mod, "_DEFAULT_CACHE_DIR", tmp_path / "_isolated_tmd_cache")
