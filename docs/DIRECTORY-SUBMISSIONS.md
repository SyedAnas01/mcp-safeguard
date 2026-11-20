# Directory + listing submissions (copy-paste)

Use after `glama.json` + Action land on `main`.

## 1. Glama

1. Open https://glama.ai/mcp/servers → **Add MCP Server**
2. Repo: `https://github.com/SyedAnas01/mcp-safeguard`
3. Display name: `mcp-safeguard`
4. Description: `Security scanner for MCP servers — prompt injection, credential leaks, SSRF, tool poisoning, source audit. Black Hat Europe Arsenal 2026.`
5. Authenticate with GitHub (personal repo → claim) or re-run claim after `glama.json` merges.

## 2. mcpservers.org / mcp.so / MCP Market / Claude Market

**Blurb (≤280 chars):**
> mcp-safeguard — open-source security scanner for MCP configs + server source. Detects prompt injection, credential leaks, SSRF, tool poisoning. `pip install mcp-safeguard`. Black Hat Europe Arsenal 2026. Built by the researcher behind CVE-2026-14540 (Google MCP Toolbox) + AWS MCP CVEs.

**Links to paste:** PyPI · GitHub · cognivators.com · official MCP registry `com.cognivators/mcp-safeguard`

## 3. awesome-mcp-servers (punkpeye)

PR after Glama listing exists (many entries want a Glama badge).

```markdown
- [mcp-safeguard](https://github.com/SyedAnas01/mcp-safeguard) - Security scanner for MCP servers (prompt injection, credentials, SSRF, tool poisoning, source audit). `pip install mcp-safeguard`.
```

Also file PRs to: `awesome-llm-security`, `awesome-ai-security` (one-line each).

## 4. GitHub Actions Marketplace

1. Merge Action PR to `main`
2. Accept [GitHub Marketplace Developer Agreement](https://docs.github.com/en/apps/publishing-apps-to-github-marketplace/github-marketplace-overview/about-github-marketplace) on the release draft page
3. Draft release tag `v0.9.5` (or reuse `v0.9.4` only if `action.yml` is on that tag — usually bump)
4. Check **Publish this Action to the GitHub Marketplace**
5. Primary category: **Security** · Secondary: **Code Quality**

Usage consumers will write:

```yaml
- uses: SyedAnas01/mcp-safeguard@v0.9.5
```

## 5. Hugging Face Space

```bash
# one-time
huggingface-cli login
huggingface-cli repo create mcp-safeguard --type space --space_sdk gradio
cd hf-space && huggingface-cli upload SyedAnas01/mcp-safeguard . --repo-type=space
```

## 6. Docker Hub / GHCR reminder

Image already referenced in README (`syedanas01/mcp-safeguard`). Confirm latest tag tracks PyPI 0.9.4+ after Action ships.
