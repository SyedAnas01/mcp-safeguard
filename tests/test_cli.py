"""Tests for the CLI scanning entrypoint."""

import json

from mcp_shield.cli import _run_scan


def test_realistic_mcp_servers_config_warns_tools_skipped(tmp_path, capsys):
    """
    A real Claude Desktop config's mcpServers entries never embed tool
    definitions inline (only command/args/env) — _extract_tools legitimately
    returns []. The CLI must warn on stderr that tool-based checks were
    skipped, rather than silently reporting a clean scan.
    """
    config = {"mcpServers": {"srv": {"command": "npx", "args": [], "env": {}}}}
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))

    _run_scan(str(config_path))

    captured = capsys.readouterr()
    assert "tool" in captured.err.lower()
    assert "skip" in captured.err.lower()
