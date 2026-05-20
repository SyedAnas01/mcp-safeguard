# Publish Commands

Run these commands to publish mcp-shield to GitHub and PyPI.

## Prerequisites

```bash
# Install GitHub CLI
brew install gh

# Log in to GitHub
gh auth login

# Set your PyPI token (from https://pypi.org/manage/account/token/)
export PYPI_TOKEN=pypi-your-token-here
```

## Step 1: Publish to GitHub

```bash
cd /Users/mr.syedanas/mcp-shield

# Create the public GitHub repository and push all code
gh repo create mcp-shield --public \
  --description "🛡️ Security scanner for MCP servers — detect prompt injection, credential leaks, exposed endpoints, and tool poisoning risks" \
  --push \
  --source .

# Add repository topics
gh repo edit mcp-shield \
  --add-topic mcp \
  --add-topic security \
  --add-topic ai-security \
  --add-topic prompt-injection \
  --add-topic model-context-protocol \
  --add-topic llm-security \
  --add-topic ai-agents \
  --add-topic claude \
  --add-topic opentelemetry

# Create v0.1.0 release
gh release create v0.1.0 \
  --title "v0.1.0 — Initial Release" \
  --notes "First public release of mcp-shield.

## Highlights
- 15+ prompt injection detection rules
- 17 credential leak patterns (AWS, Anthropic, GitHub, Stripe, JWT, etc.)
- 28 sensitive endpoint probes + 12 dangerous port checks
- Tool blast radius scoring (0–10) and poisoning detection
- CVSS-scored findings with step-by-step remediation
- HTML + JSON security reports
- Prometheus metrics and OpenTelemetry tracing
- 73 passing tests

## Install
\`\`\`bash
pip install mcp-shield
\`\`\`

See [README](https://github.com/mcp-shield/mcp-shield#readme) for full documentation." \
  dist/mcp_shield-0.1.0.tar.gz \
  dist/mcp_shield-0.1.0-py3-none-any.whl
```

## Step 2: Publish to PyPI

```bash
cd /Users/mr.syedanas/mcp-shield

# Upload to PyPI
TWINE_PASSWORD=$PYPI_TOKEN .venv/bin/twine upload dist/* --username __token__

# Verify installation
pip install mcp-shield
```

## Step 3: Verify

```bash
# Test the installed package
python -c "import mcp_shield; print(mcp_shield.__version__)"

# Run the server
fastmcp run src/mcp_shield/server.py
```
