# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in mcp-shield, please report it responsibly:

1. **Email**: Send details to the maintainers via GitHub's private security advisory feature:
   `https://github.com/mcp-shield/mcp-shield/security/advisories/new`

2. **Include in your report**:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Any suggested fixes (optional but appreciated)

3. **Response timeline**:
   - Acknowledgement within 48 hours
   - Initial assessment within 5 business days
   - Fix and disclosure within 30 days for critical issues

## Scope

Security issues we want to hear about:
- SSRF vulnerabilities in the scanner
- Authentication bypass
- Path traversal in report file handling
- Credential exposure in logs or API responses
- Dependencies with known CVEs

## Out of Scope

- Issues that require physical access to the machine
- Issues in dependencies that are already publicly disclosed and tracked upstream
- Theoretical attacks without proof of concept

## Disclosure Policy

We follow coordinated disclosure. Once a fix is available, we will:
1. Release a patched version
2. Publish a GitHub Security Advisory
3. Credit the reporter (if desired)

Thank you for helping keep mcp-shield and its users secure.
