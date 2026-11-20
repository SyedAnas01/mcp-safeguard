"""Hugging Face Space demo for mcp-safeguard.

Deploy: create a Gradio Space, set SDK=gradio, copy this file + requirements.txt.
Runs config scans only (no arbitrary remote source clones) so the Space stays safe.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import gradio as gr

DEMO = {
    "mcpServers": {
        "demo-vulnerable": {
            "command": "npx",
            "args": ["-y", "demo-mcp-server"],
            "env": {
                "API_KEY": "sk-live-EXAMPLE_DO_NOT_USE",
                "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            },
        }
    }
}


def run_scan(config_text: str, fail_on: str, severity: str) -> str:
    try:
        data = json.loads(config_text)
    except json.JSONDecodeError as exc:
        return f"Invalid JSON: {exc}"

    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "config.json"
        out = Path(tmp) / "report.json"
        cfg.write_text(json.dumps(data, indent=2))
        cmd = [
            "mcp-safeguard",
            "scan",
            str(cfg),
            "--severity",
            severity,
            "--fail-on",
            fail_on,
            "--format",
            "json",
            "--output",
            str(out),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        body = out.read_text() if out.exists() else proc.stdout
        footer = f"\n\n---\nexit={proc.returncode}\n{proc.stderr.strip()}"
        return (body or "(no findings file)") + footer


with gr.Blocks(title="mcp-safeguard") as demo:
    gr.Markdown(
        """
# mcp-safeguard
Security scanner for MCP configs — prompt injection, credential leaks, SSRF, tool poisoning.

`pip install mcp-safeguard` · [GitHub](https://github.com/SyedAnas01/mcp-safeguard) · Black Hat Europe Arsenal 2026
"""
    )
    config = gr.Code(
        value=json.dumps(DEMO, indent=2),
        language="json",
        label="MCP config JSON",
        lines=18,
    )
    with gr.Row():
        fail_on = gr.Dropdown(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            value="HIGH",
            label="fail-on",
        )
        severity = gr.Dropdown(
            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
            value="INFO",
            label="min severity",
        )
    btn = gr.Button("Scan", variant="primary")
    result = gr.Code(label="Findings (JSON)", language="json", lines=22)
    btn.click(run_scan, inputs=[config, fail_on, severity], outputs=result)

if __name__ == "__main__":
    demo.launch()
