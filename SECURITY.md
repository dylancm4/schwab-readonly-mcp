# Security Policy

`schwab-readonly-mcp` is a personal-use, single-maintainer tool that touches a brokerage OAuth token. Reports affecting the integrity of that boundary are taken seriously, on a best-effort basis.

## Reporting a vulnerability

Please use GitHub's private reporting flow — click **"Report a vulnerability"** on the [Security tab](https://github.com/dylancm4/schwab-readonly-mcp/security), or open one directly via the [new advisory](https://github.com/dylancm4/schwab-readonly-mcp/security/advisories/new) page. This keeps the issue private until a patched release is published.

Please do not file public issues for security-sensitive findings.

## In scope

- Bugs in `auth.py`, `client.py`, or `server.py` that could leak OAuth tokens, account data, or transaction history outside the local MCP stdio channel.
- Bugs that allow a write/mutation against the Schwab API despite the documented read-only guarantees.
- Dependency vulnerabilities not already addressed by the pinned versions in `uv.lock`.

## Out of scope

- Bugs in upstream dependencies (`mcp`, `httpx`, `keyring`) that don't manifest as exploitable issues in this code — report those to the upstream projects.
- Attacks requiring local root access on the machine running the server (this is a personal tool, not a hosted service).
- Feature requests, usability issues, or non-security bugs — open a regular issue instead.

## Response

Best-effort, single-maintainer. There is no SLA. Triage typically within a week during active periods, longer if the project is idle. If you don't hear back within two weeks, feel free to nudge by commenting on the advisory.
