# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, email: cognivators@gmail.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

We will respond within 48 hours and aim to release a patch within 7 days for critical issues.

## Security Design

mcp-safeguard itself follows these security practices:
- All scan inputs are validated and sanitized before use
- SSRF protection: only localhost is scannable by default
- Token-bucket rate limiting prevents abuse
- Authentication via constant-time HMAC comparison
- Structured audit logging for all tool calls
- No credentials are stored — only masked (first 4 + last 4 chars) in reports
