# schwab-readonly-mcp

A minimal, auditable, **read-only** [Model Context Protocol](https://modelcontextprotocol.io/) server that exposes a personal Charles Schwab brokerage account to local LLM tooling (e.g. Claude Code).

Written from scratch — no third-party Schwab SDK, no aggregators — so the entire surface a Schwab access token touches can be read end-to-end in a single sitting.

> **Status: bootstrap.** This repository currently contains only project scaffolding (pinned dependencies, license, layout). The auth module, REST client, and MCP server will land in subsequent commits.

## Disclaimer

Not affiliated with or endorsed by The Charles Schwab Corporation. Schwab and related marks are trademarks of their respective owners.

This is a personal-use tool. The author makes no warranty as to its correctness or fitness for any purpose. Read the code before running it against a real account.

## Audit promise

This server is structured so that three properties are mechanically verifiable, not just claimed:

1. **Read-only at the source level.** No `httpx.post`, `httpx.put`, `httpx.delete`, or `httpx.patch` calls anywhere in `src/`. Verified by `grep`. There is no code path that can place, cancel, or modify an order.
2. **No tokens on disk.** OAuth tokens (access, refresh, expiry) live only in the macOS Keychain under the service name `schwab-readonly-mcp`. No file-based fallback exists in the source. Verified by `grep` for `open(` / `with open` in `src/schwab_readonly_mcp/auth.py`.
3. **Pinned, hash-locked dependencies.** `pyproject.toml` uses `==` exact-version pins. `uv.lock` contains SHA-256 hashes for every transitive dependency. `uv sync --frozen` fails if anything has drifted.

Total source budget when complete: roughly 300 lines across three files. The point is that one person can read all of it in an afternoon.

## Dependencies

Runtime (3):

| Package | Version | Purpose |
| --- | --- | --- |
| [`mcp`](https://pypi.org/project/mcp/) | 1.27.1 | Anthropic's Python MCP SDK; provides the `FastMCP` server. |
| [`httpx`](https://pypi.org/project/httpx/) | 0.28.1 | HTTPS client for the Schwab REST API. |
| [`keyring`](https://pypi.org/project/keyring/) | 25.7.0 | Cross-platform credential store; uses macOS Keychain on darwin. |

Dev (3):

| Package | Version | Purpose |
| --- | --- | --- |
| [`pytest`](https://pypi.org/project/pytest/) | 9.0.3 | Test runner. |
| [`pytest-asyncio`](https://pypi.org/project/pytest-asyncio/) | 1.3.0 | Async test support. |
| [`respx`](https://pypi.org/project/respx/) | 0.23.1 | Mocks `httpx` requests in unit tests. |

No `schwab-py`, no community Schwab MCPs, no third-party aggregator SDKs.

## Tool surface (planned)

Exactly five MCP tools will be exposed, all read-only:

- `list_accounts`
- `get_account`
- `get_transactions`
- `get_quotes`
- `get_price_history`

A guardrail test in `tests/test_server.py` asserts this set exactly, and that no tool name contains any case-insensitive substring from `{place, submit, cancel, order, trade, buy, sell}`.

## Install (once complete)

Requires Python 3.14 and [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/dylancm4/schwab-readonly-mcp.git
cd schwab-readonly-mcp
uv sync --frozen
```

First-run OAuth (one-time, requires a Schwab Developer App in "Ready For Use" state):

```bash
export SCHWAB_CLIENT_ID=...
export SCHWAB_CLIENT_SECRET=...
uv run python scripts/authorize.py
```

Then register with your MCP-aware client (e.g. add an entry to Claude Code's `.claude/settings.json`).

## Updating dependencies

The auditability promise only holds if updates are reviewed deliberately rather than swept in by a `latest`-style upgrade.

To bump a single package:

```bash
uv lock --upgrade-package <name>
git diff uv.lock
```

Read the diff. Confirm the version bump is intentional, look at any newly-pulled transitive dependencies, then commit `pyproject.toml` (if the pin changed) and `uv.lock` together.

Never edit `uv.lock` by hand. Never run a bare `uv lock --upgrade` (it bumps every package at once and produces an unreviewable diff).

## License

[MIT](LICENSE) (c) 2026 Dylan Miller.
