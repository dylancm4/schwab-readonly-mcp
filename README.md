# schwab-readonly-mcp

A minimal, auditable, **read-only** [Model Context Protocol](https://modelcontextprotocol.io/) server that exposes a personal Charles Schwab brokerage account to local LLM tooling (e.g. Claude Code).

Written from scratch — no third-party Schwab SDK, no aggregators — so the entire surface a Schwab access token touches can be read end-to-end in a single sitting.

> **Status: runnable end-to-end.** The auth module (Keychain token storage + OAuth refresh), the read-only REST client, the MCP server entry point, and the one-time authorization helper (`scripts/authorize.py`) have all landed, each with test coverage. Follow [Install](#install) to authorize and wire it into Claude Code.

## Disclaimer

Not affiliated with or endorsed by The Charles Schwab Corporation. Schwab and related marks are trademarks of their respective owners.

This is a personal-use tool. The author makes no warranty as to its correctness or fitness for any purpose. Read the code before running it against a real account.

## Audit promise

This server is structured so that three properties are mechanically verifiable, not just claimed. All three are verifiable today against the code in this repository.

1. **Read-only against Schwab.** `src/schwab_readonly_mcp/client.py` — the only module that talks to the Schwab data APIs — makes exactly one HTTP call: `client.get(...)`. That no write reaches Schwab in any form is backed by two zero-match greps: `grep -nE "\.(post|put|delete|patch)\(" src/schwab_readonly_mcp/client.py` (no write-verb method call — bound `client.post(...)` or `httpx.`-prefixed) and `grep -nE "\.(request|send|stream|build_request)\(" src/schwab_readonly_mcp/client.py` (no generic dispatcher that could carry a write verb). There is no code path that can place, cancel, or modify an order. (`auth.py` does POST to Schwab's OAuth token endpoint to obtain and refresh access tokens; that's authentication, not account-state mutation — which is why these checks are scoped to `client.py`.)
2. **No tokens on disk.** OAuth tokens (access, refresh, expiry) live only in the macOS Keychain under the service name `schwab-readonly-mcp`. No file-based fallback exists in the source. Verified by `grep -nE "open\(|with open" src/schwab_readonly_mcp/auth.py` (zero matches).
3. **Pinned, hash-locked dependencies.** `pyproject.toml` uses `==` exact-version pins. `uv.lock` contains SHA-256 hashes for every transitive dependency. `uv sync --frozen` fails if anything has drifted.

Total source: roughly 500 lines across three modules (`auth.py`, `client.py`, `server.py`), plus a ~220-line one-time authorization script (`scripts/authorize.py`). The point is that one person can read all of it in an afternoon.

## Dependencies

Runtime (3):

| Package | Version | Purpose |
| --- | --- | --- |
| [`mcp`](https://pypi.org/project/mcp/) | 1.27.1 | Official Python SDK for the Model Context Protocol; provides the `FastMCP` server. |
| [`httpx`](https://pypi.org/project/httpx/) | 0.28.1 | HTTPS client for the Schwab REST API. |
| [`keyring`](https://pypi.org/project/keyring/) | 25.7.0 | Credential store; this project targets the macOS Keychain backend specifically. |

Dev (3):

| Package | Version | Purpose |
| --- | --- | --- |
| [`pytest`](https://pypi.org/project/pytest/) | 9.0.3 | Test runner. |
| [`pytest-asyncio`](https://pypi.org/project/pytest-asyncio/) | 1.3.0 | Async test support. |
| [`respx`](https://pypi.org/project/respx/) | 0.23.1 | Mocks `httpx` requests in unit tests. |

No `schwab-py`, no community Schwab MCPs, no third-party aggregator SDKs.

## Tool surface

Exactly five MCP tools are exposed, all read-only:

- `list_accounts` — returns `{"accounts": [...]}` (envelope, see below).
- `get_account`
- `get_transactions` — accepts an optional `types` filter (comma-separated Schwab transaction types, e.g. `TRADE,DIVIDEND_OR_INTEREST`); it defaults to all 15 types, i.e. no filtering, and is always sent on the wire (the endpoint misbehaves without it). Returns `{"transactions": [...]}` (envelope, see below).
- `get_quotes`
- `get_price_history`

The per-account tools (`get_account`, `get_transactions`) take the plaintext account number, but Schwab's per-account endpoints only accept the encrypted account hash — so the client first resolves the number via `GET /trader/v1/accounts/accountNumbers` (another plain GET; the read-only audit promise is unchanged). The number→hash mapping is cached in memory for the life of the client instance only, never written to disk.

Tools return Schwab's parsed JSON unmodified, with one exception: Schwab returns a top-level JSON **array** from the accounts and transactions endpoints, and FastMCP serializes a list-valued tool result as one content block *per element* — a naive MCP client reads only the first block and silently sees one account instead of six. `list_accounts` and `get_transactions` therefore wrap the raw array (intact and in order) in a stable single-key envelope, `{"accounts": [...]}` and `{"transactions": [...]}` respectively, unconditionally. A test in `tests/test_server.py` pins that every tool's result serializes to exactly one content block.

A guardrail test in `tests/test_server.py` asserts this set exactly, and that no tool name contains any case-insensitive substring from `{place, submit, cancel, order, trade, buy, sell}`.

## Install

**Platform: macOS only.** Token storage is keyed to the macOS Keychain via the `keyring` library's `darwin` backend. The `keyring` library itself is cross-platform, but this project does not target or test on Linux or Windows; the audit-promise statement about "OAuth tokens live only in the macOS Keychain" assumes you are running on macOS. Porting would require an explicit choice of Linux/Windows backend (Secret Service, Credential Manager, etc.) and is out of scope.

Requires Python 3.14 and [`uv`](https://docs.astral.sh/uv/). (3.14 was the current stable when this project was bootstrapped; no 3.14-specific language features are used, so the floor can be lowered if needed.)

You also need a [Schwab Developer App](https://developer.schwab.com/) in **"Ready For Use"** state, with its callback URL set to exactly `https://127.0.0.1:8182` (no trailing slash — Schwab does an exact-string comparison). Its **App Key** and **Secret** are your `SCHWAB_CLIENT_ID` and `SCHWAB_CLIENT_SECRET`.

```bash
git clone https://github.com/dylancm4/schwab-readonly-mcp.git
cd schwab-readonly-mcp
uv sync --frozen
```

### First-run OAuth (one-time)

1. Export your Schwab Developer App credentials into the shell. These come from the Developer Portal; do not commit them.

   ```bash
   export SCHWAB_CLIENT_ID=...
   export SCHWAB_CLIENT_SECRET=...
   ```

2. Generate a one-day self-signed localhost cert. Schwab requires the OAuth callback to be HTTPS; `scripts/authorize.py` reads this cert/key from system `/tmp` — outside the repo worktree, so git never sees them — and `.gitignore`'s unanchored `*.pem` rule additionally catches any pem that strays into the repo.

   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem \
       -days 1 -nodes -subj '/CN=127.0.0.1'
   ```

3. Run the authorization helper. It opens your browser to Schwab's login/consent page, captures the redirect on a single-use `https://127.0.0.1:8182` server, exchanges the returned code for tokens, and stores them in the Keychain.

   ```bash
   uv run python scripts/authorize.py
   ```

   Your browser will warn about the self-signed cert on `127.0.0.1` — that is expected; proceed. macOS will prompt for **Keychain access** the first time tokens are stored; approve it.

4. Smoke-test it. The helper prints this exact one-liner on success; it fetches a (possibly refreshed) access token, lists your accounts, and prints a **truncated** JSON dump (never tokens). Confirm the holdings match what you see on schwab.com.

   ```bash
   uv run python -c 'import asyncio, json; from schwab_readonly_mcp import auth; from schwab_readonly_mcp.client import SchwabClient; import os; cid=os.environ["SCHWAB_CLIENT_ID"]; csec=os.environ["SCHWAB_CLIENT_SECRET"]; tok=asyncio.run(auth.get_access_token(cid, csec)); data=asyncio.run(SchwabClient(tok).list_accounts()); s=json.dumps(data, indent=2); print(s[:2000] + ("\n... [truncated]" if len(s) > 2000 else ""))'
   ```

### Wire into Claude Code

Claude Code reads MCP servers from a project-root `.mcp.json` (or registers them via `claude mcp add`), not from `.claude/settings.json`. The server's runtime needs `SCHWAB_CLIENT_ID` and `SCHWAB_CLIENT_SECRET` in its environment (to refresh access tokens); the refresh token itself stays in the Keychain.

Add this to `.mcp.json` in the project where you want the tools available:

```json
{
  "mcpServers": {
    "schwab-readonly": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/schwab-readonly-mcp", "schwab-readonly-mcp"],
      "env": {
        "SCHWAB_CLIENT_ID": "${SCHWAB_CLIENT_ID}",
        "SCHWAB_CLIENT_SECRET": "${SCHWAB_CLIENT_SECRET}"
      }
    }
  }
}
```

The `${VAR}` references are expanded by Claude Code from your shell environment at launch. **Never paste the literal credential values into `.mcp.json` or any other file that can be committed** — keep them in the shell environment only (`.mcp.json` is conventionally checked in, which is exactly how an app secret ends up in a repo).

To make those exports permanent without writing the values into a dotfile, store both in the Keychain — the same place the OAuth tokens live. Each command prompts for the value, so it never enters your shell history:

```bash
security add-generic-password -a "$USER" -s schwab-client-id -w
security add-generic-password -a "$USER" -s schwab-client-secret -w
```

Then have `~/.zshrc` read them back on every new shell (if a lookup fails the variable is exported empty; the server refuses to start on an empty value, with a clear error):

```zsh
export SCHWAB_CLIENT_ID="$(security find-generic-password -s schwab-client-id -w 2>/dev/null)"
export SCHWAB_CLIENT_SECRET="$(security find-generic-password -s schwab-client-secret -w 2>/dev/null)"
```

Apps that resolve your login shell's environment at launch (VS Code does — it runs your shell once at startup and caches the result) need a full restart, not a window reload, after adding these lines; GUI apps that never do this will not see the variables at all.

Instead of `.mcp.json`, you can register the server from the command line — but note this is *not* equivalent: your shell expands `"${SCHWAB_CLIENT_ID}"` at `add` time, so the literal values are written into `~/.claude.json` in your home directory (outside any repo, but plaintext on disk; Claude Code documents `${VAR}` expansion only for `.mcp.json`, so prefer the `.mcp.json` form above, which stores only the references):

```bash
claude mcp add schwab-readonly \
  -e SCHWAB_CLIENT_ID="${SCHWAB_CLIENT_ID}" -e SCHWAB_CLIENT_SECRET="${SCHWAB_CLIENT_SECRET}" \
  -- uv run --directory /absolute/path/to/schwab-readonly-mcp schwab-readonly-mcp
```

### Re-authorizing

Schwab refresh tokens expire after **7 days**. The server refreshes the short-lived access token transparently, but if the server goes unused for 7+ days the refresh token lapses and the next call fails. Re-run the one-time OAuth flow above (`scripts/authorize.py`) to mint a fresh pair.

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
