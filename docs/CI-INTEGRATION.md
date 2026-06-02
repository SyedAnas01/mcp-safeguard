# CI/CD Integration Guide for mcp-safeguard

Integrate `mcp-safeguard` into your development workflow to automatically detect prompt injection, tool poisoning, and authentication vulnerabilities in your MCP server before they reach production.

---

## 3 Ways to Integrate mcp-safeguard

### 1. Simple One-Liner

The fastest way to get a security scan — no configuration needed. Run this in any shell (locally or in a CI script):

```bash
pip install mcp-safeguard && mcp-safeguard scan http://localhost:8000
```

To fail your pipeline when HIGH or CRITICAL findings are detected:

```bash
pip install mcp-safeguard && mcp-safeguard scan http://localhost:8000 --fail-on-high
```

Save a JSON report for later review:

```bash
mcp-safeguard scan http://localhost:8000 \
  --output json \
  --report-file mcp-security-report.json \
  --fail-on-high
```

---

### 2. GitHub Actions Workflow

Drop this workflow into your repository at `.github/workflows/mcp-security-scan.yml`. It runs on every push, every pull request, and on a weekly schedule.

**Prerequisites:**
- Add your MCP server URL as a GitHub secret: `MCP_SERVER_URL`
  - Navigate to: **Repo → Settings → Secrets and variables → Actions → New repository secret**

```yaml
name: MCP Security Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]
  schedule:
    - cron: "0 8 * * 1"   # Every Monday at 08:00 UTC

jobs:
  mcp-security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install mcp-safeguard
        run: pip install mcp-safeguard

      - name: Run security scan
        env:
          MCP_SERVER_URL: ${{ secrets.MCP_SERVER_URL }}
        run: |
          mcp-safeguard scan "$MCP_SERVER_URL" \
            --output json \
            --report-file mcp-security-report.json \
            --fail-on-high

      - name: Upload report artifact
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: mcp-security-report
          path: mcp-security-report.json
          retention-days: 30
```

The full workflow — including automatic PR comment posting with a findings summary table — is available at [`.github/workflows/mcp-security-scan.yml`](../.github/workflows/mcp-security-scan.yml).

**What you get:**
- CI fails automatically if HIGH or CRITICAL vulnerabilities are found
- JSON report uploaded as a downloadable artifact on every run
- PR comment posted with per-severity finding counts and a pass/fail badge
- Weekly scheduled scans to catch newly discovered attack patterns

---

### 3. Pre-Commit / Pre-Deploy Hook

Run mcp-safeguard as a gate before deploying to staging or production. Add this to your deploy script or as a shell alias:

**As a pre-deploy shell script (`scripts/pre-deploy-security-check.sh`):**

```bash
#!/usr/bin/env bash
# Run mcp-safeguard before any deployment.
# Set MCP_STAGING_URL in your environment or .env file.
set -euo pipefail

MCP_SERVER_URL="${MCP_STAGING_URL:-http://localhost:8000}"

echo "[mcp-safeguard] Scanning $MCP_SERVER_URL before deploy..."

pip install mcp-safeguard --quiet

mcp-safeguard scan "$MCP_SERVER_URL" \
  --output json \
  --report-file pre-deploy-mcp-report.json \
  --fail-on-high

echo "[mcp-safeguard] Scan passed — proceeding with deploy."
```

Make it executable and wire it into your deploy pipeline:

```bash
chmod +x scripts/pre-deploy-security-check.sh

# Example: add to your Makefile
deploy: pre-deploy-security-check.sh
    ./scripts/pre-deploy-security-check.sh
    kubectl apply -f k8s/
```

**As a git pre-push hook (`.git/hooks/pre-push`):**

```bash
#!/usr/bin/env bash
# Blocks git push if the local MCP server has HIGH/CRITICAL findings.
# Requires the MCP server to be running locally when you push.

if command -v mcp-safeguard &>/dev/null; then
  echo "[mcp-safeguard] Running pre-push security check..."
  mcp-safeguard scan http://localhost:8000 --fail-on-high --output text
  if [ $? -ne 0 ]; then
    echo "[mcp-safeguard] Push blocked: HIGH or CRITICAL findings detected."
    echo "Run 'mcp-safeguard scan http://localhost:8000' to see details."
    exit 1
  fi
fi
```

---

## Scan Coverage

Each scan checks for:

| Category | Examples |
|---|---|
| Prompt Injection | Direct injection via tool parameters, indirect injection via retrieved content |
| Tool Poisoning | Malicious tool descriptions that hijack agent behavior |
| Authentication Bypass | Unauthenticated endpoints, weak token validation |
| Data Exfiltration Vectors | Tools that leak environment variables or file contents |
| Excessive Permissions | Tools with broader scope than declared |

Run `mcp-safeguard list-checks` to see all 52 detection rules.

---

## Interpreting Results

| Severity | Meaning | Recommended Action |
|---|---|---|
| CRITICAL | Active exploit path confirmed | Block deploy, fix immediately |
| HIGH | Strong evidence of vulnerability | Block deploy, fix before merge |
| MEDIUM | Potential weakness, context-dependent | Fix within current sprint |
| LOW | Defense-in-depth improvement | Fix within 30 days |
| INFO | Informational finding | Review at your discretion |

With `--fail-on-high`, CI fails on CRITICAL and HIGH. MEDIUM, LOW, and INFO findings are reported but do not block the pipeline.

---

## Resources

- GitHub: [gitlab.com/anasmohiuddinsyed/mcp-safeguard](https://gitlab.com/anasmohiuddinsyed/mcp-safeguard)
- PyPI: [pypi.org/project/mcp-safeguard](https://pypi.org/project/mcp-safeguard)
- Full CLI reference: `mcp-safeguard --help`
- Report a false positive: open an issue with the `false-positive` label
