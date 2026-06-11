import os
from importlib.metadata import entry_points
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from schwab_readonly_mcp import client, server

EXPECTED_TOOLS = {
    "list_accounts",
    "get_account",
    "get_transactions",
    "get_quotes",
    "get_price_history",
}

# Any of these case-insensitive substrings in an exposed tool name would mean a
# write/trade capability has leaked into this read-only server.
WRITE_SUBSTRINGS = {"place", "submit", "cancel", "order", "trade", "buy", "sell"}


class TestServerToolSurface:
    async def test_server_exposes_only_expected_tools(self):
        # The real protocol surface — what an MCP client actually sees — must be
        # EXACTLY the five read-only tools. A symmetric difference names both any
        # missing tool and any unexpected extra, so either failure mode is loud.
        exposed = {tool.name for tool in await server.mcp.list_tools()}
        diff = exposed ^ EXPECTED_TOOLS
        assert not diff, f"tool surface drifted: {sorted(diff)}"

    async def test_server_has_no_write_tools(self):
        # Long-term safety net: even if a future edit adds a tool, this fails the
        # build the moment any exposed name hints at a write/trade verb.
        exposed = {tool.name for tool in await server.mcp.list_tools()}
        offenders = {
            name
            for name in exposed
            if any(bad in name.lower() for bad in WRITE_SUBSTRINGS)
        }
        assert not offenders, f"write-capable tool name(s) exposed: {sorted(offenders)}"


class TestConsoleScriptEntryPoint:
    def test_entry_point_resolves_to_mcp_run(self):
        # pyproject wires the installed `schwab-readonly-mcp` command (and the
        # README .mcp.json) to "schwab_readonly_mcp.server:mcp.run". A rename of
        # the module-level `mcp` would break that at runtime only — pin that the
        # entry point exists and resolves to the real server's run method.
        (ep,) = entry_points(group="console_scripts", name="schwab-readonly-mcp")
        run = ep.load()
        assert callable(run)
        assert run == server.mcp.run


def _patched_client():
    # Replace server._client with an AsyncMock returning a fake SchwabClient whose
    # methods are AsyncMocks. Returns (patcher-context, fake_client); each test sets
    # a distinct return_value on the method it exercises so a wrong method binding
    # can't accidentally pass.
    fake = AsyncMock()
    return patch.object(server, "_client", AsyncMock(return_value=fake)), fake


class TestServerDispatch:
    # Pin the actual dispatch: each tool must await the matching SchwabClient
    # method exactly once with the exact positional args/defaults and return its
    # result. A swapped/dropped arg, wrong default, or wrong method binding (which
    # the name-surface tests can't see) fails here.

    async def test_list_accounts_forwards_default_true(self):
        ctx, fake = _patched_client()
        fake.list_accounts.return_value = "SENTINEL_LIST"
        with ctx:
            result = await server.list_accounts()
        assert result == "SENTINEL_LIST"
        fake.list_accounts.assert_awaited_once_with(True)

    async def test_get_account_forwards_args_in_order(self):
        ctx, fake = _patched_client()
        fake.get_account.return_value = "SENTINEL_ACCT"
        with ctx:
            result = await server.get_account("ACC123", False)
        assert result == "SENTINEL_ACCT"
        fake.get_account.assert_awaited_once_with("ACC123", False)

    async def test_get_account_default_include_positions_true(self):
        ctx, fake = _patched_client()
        fake.get_account.return_value = "SENTINEL_ACCT"
        with ctx:
            await server.get_account("ACC123")
        fake.get_account.assert_awaited_once_with("ACC123", True)

    async def test_get_transactions_forwards_args_in_order(self):
        ctx, fake = _patched_client()
        fake.get_transactions.return_value = "SENTINEL_TXN"
        with ctx:
            result = await server.get_transactions("ACC", "s", "e")
        assert result == "SENTINEL_TXN"
        fake.get_transactions.assert_awaited_once_with("ACC", "s", "e")

    async def test_get_quotes_forwards_symbols(self):
        ctx, fake = _patched_client()
        fake.get_quotes.return_value = "SENTINEL_QUOTES"
        with ctx:
            result = await server.get_quotes(["A", "B"])
        assert result == "SENTINEL_QUOTES"
        fake.get_quotes.assert_awaited_once_with(["A", "B"])

    async def test_get_price_history_forwards_five_positional_args(self):
        ctx, fake = _patched_client()
        fake.get_price_history.return_value = "SENTINEL_HIST"
        with ctx:
            result = await server.get_price_history("AAPL", "day", 1, "minute", 5)
        assert result == "SENTINEL_HIST"
        fake.get_price_history.assert_awaited_once_with("AAPL", "day", 1, "minute", 5)


class TestAuthClientSeam:
    # The dispatch tests above replace _client() wholesale, so nothing there can
    # see WHICH value the real _client() hands to SchwabClient. This is the one
    # test that executes the real _client(): it pins that the token returned by
    # auth.get_access_token — not the client_id, not "" — is the exact Bearer
    # credential on the wire, and that the credentials tuple feeds the getter.

    @respx.mock
    async def test_access_token_from_auth_becomes_bearer_credential(self):
        route = respx.get(f"{client.BASE_URL}/trader/v1/accounts").mock(
            return_value=httpx.Response(200, json=[])
        )
        creds = patch.object(server, "_credentials", return_value=("cid", "csec"))
        getter = AsyncMock(return_value="TOK")
        with creds, patch.object(server.auth, "get_access_token", getter):
            result = await server.list_accounts()
        assert result == []
        getter.assert_awaited_once_with("cid", "csec")
        req = route.calls.last.request
        assert req.headers["authorization"] == "Bearer TOK"


class TestCredentials:
    # _credentials() is the security-relevant credential gate. Pin that it raises
    # a CLEAR RuntimeError (never a raw KeyError) on missing/empty/partial config
    # and never echoes the values, and that the happy path returns the tuple.

    @pytest.mark.parametrize(
        "env",
        [
            {},
            {"SCHWAB_CLIENT_ID": "the-id-value"},
            {"SCHWAB_CLIENT_SECRET": "the-secret-value"},
            {"SCHWAB_CLIENT_ID": "the-id-value", "SCHWAB_CLIENT_SECRET": ""},
            {"SCHWAB_CLIENT_ID": "", "SCHWAB_CLIENT_SECRET": "the-secret-value"},
            {"SCHWAB_CLIENT_ID": "", "SCHWAB_CLIENT_SECRET": ""},
        ],
    )
    def test_missing_or_empty_raises_clean_runtime_error(self, env):
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(RuntimeError) as excinfo:
                server._credentials()
        # A regression to os.environ[...] would surface a KeyError, defeating the
        # "clear operator error" contract.
        assert not isinstance(excinfo.value, KeyError)
        # The error must name only the absence, never echo a configured value.
        message = str(excinfo.value)
        assert "the-id-value" not in message
        assert "the-secret-value" not in message

    def test_happy_path_returns_tuple(self):
        env = {"SCHWAB_CLIENT_ID": "cid", "SCHWAB_CLIENT_SECRET": "csec"}
        with patch.dict(os.environ, env, clear=True):
            assert server._credentials() == ("cid", "csec")


class TestErrorPropagation:
    # LOCKED decision: auth/client errors propagate UNCAUGHT (re-stringifying could
    # leak a secret). Pin IDENTITY on the direct module-fn path (the very object the
    # mock raised, unwrapped and unmodified — a wrap/re-stringify would fail it) and
    # that the secret-bearing exception chain stays severed.

    async def test_scrubbed_runtime_error_propagates_without_secret(self):
        sentinel_err = RuntimeError("Schwab API returned HTTP 401")
        creds = patch.object(server, "_credentials", return_value=("cid", "csec"))
        getter = patch.object(
            server.auth, "get_access_token", AsyncMock(side_effect=sentinel_err)
        )
        with creds, getter:
            with pytest.raises(RuntimeError) as excinfo:
                await server.list_accounts()
        exc = excinfo.value
        # Propagates UNCAUGHT and UNMODIFIED: the exact object, never a rebuilt
        # message that could embed a secret.
        assert exc is sentinel_err
        # Direct module-fn path: nothing re-raises, so the chain to any
        # secret-bearing error must stay None.
        assert exc.__context__ is None
        assert exc.__cause__ is None

    async def test_call_tool_surface_does_not_leak_secret_through_chain(self):
        # The direct module-fn tests above prove OUR code severs the chain. But the
        # real protocol surface is mcp.call_tool(...), where FastMCP's Tool.run wraps
        # our scrubbed error via `raise ToolError(...) from e`. That re-link is a
        # transitive property of a pinned third-party f-string; pin it here so a
        # future mcp bump that surfaces a link still carrying the live .request, or
        # rebuilds (rather than links) our scrubbed error, fails the build.
        sentinel_err = RuntimeError("Schwab API returned HTTP 401")
        creds = patch.object(server, "_credentials", return_value=("cid", "csec"))
        getter = patch.object(
            server.auth, "get_access_token", AsyncMock(side_effect=sentinel_err)
        )
        with creds, getter:
            with pytest.raises(Exception) as excinfo:  # noqa: PT011 - walking the chain
                await server.mcp.call_tool("list_accounts", {})
        # Walk the FULL exception chain (the wrapper plus every __context__/__cause__
        # link). No link may expose a non-None .request attribute (that would be a
        # live secret-bearing httpx req), and our scrubbed error must appear in the
        # chain as the SAME object the tool raised — unmodified.
        exc = excinfo.value
        seen = set()
        found_sentinel = False
        while exc is not None and id(exc) not in seen:
            seen.add(id(exc))
            assert getattr(exc, "request", None) is None
            found_sentinel = found_sentinel or exc is sentinel_err
            exc = exc.__cause__ or exc.__context__
        assert found_sentinel

    async def test_secret_bearing_value_error_not_leaked(self):
        # A ValueError on the auth path must also surface as the exact object —
        # a future edit that re-stringified the underlying error would fail here.
        sentinel_err = ValueError("token endpoint returned invalid token")
        creds = patch.object(server, "_credentials", return_value=("cid", "csec"))
        getter = patch.object(
            server.auth, "get_access_token", AsyncMock(side_effect=sentinel_err)
        )
        with creds, getter:
            with pytest.raises(ValueError) as excinfo:
                await server.get_quotes(["AAPL"])
        exc = excinfo.value
        assert exc is sentinel_err
        assert exc.__context__ is None
        assert exc.__cause__ is None


class TestToolInputSchemas:
    # The 5 per-tool typed signatures exist so FastMCP derives correct input
    # schemas (a LOCKED reason they must stay). Pin required sets / key props so a
    # dropped param, flipped default, or widened type fails the build.

    async def _schemas(self):
        return {t.name: t.inputSchema for t in await server.mcp.list_tools()}

    async def test_get_price_history_required_set(self):
        schema = (await self._schemas())["get_price_history"]
        assert set(schema["required"]) == {
            "symbol",
            "period_type",
            "period",
            "frequency_type",
            "frequency",
        }

    async def test_get_transactions_required_set(self):
        schema = (await self._schemas())["get_transactions"]
        assert set(schema["required"]) == {
            "account_number",
            "start_date",
            "end_date",
        }

    async def test_get_account_required_set(self):
        schema = (await self._schemas())["get_account"]
        assert set(schema["required"]) == {"account_number"}

    async def test_list_accounts_requires_nothing(self):
        # Full symmetry: every tool's required set is pinned.
        schema = (await self._schemas())["list_accounts"]
        assert set(schema.get("required", [])) == set()

    async def test_get_quotes_symbols_is_array(self):
        schema = (await self._schemas())["get_quotes"]
        assert schema["properties"]["symbols"]["type"] == "array"
        assert set(schema["required"]) == {"symbols"}

    @pytest.mark.parametrize("name", ["list_accounts", "get_account"])
    async def test_include_positions_default_true_boolean(self, name):
        schema = (await self._schemas())[name]
        prop = schema["properties"]["include_positions"]
        assert prop["type"] == "boolean"
        assert prop["default"] is True
        # An optional flag must never be required.
        assert "include_positions" not in schema.get("required", [])

    async def test_no_tool_has_constraining_output_schema(self):
        # Pins the LOCKED decision: `-> object` means FastMCP emits NO output
        # schema, so raw JSON of any shape (e.g. list_accounts' array) passes
        # through unvalidated. A future annotation like `-> dict` would emit a
        # constraining schema and break list-shaped responses at runtime.
        for tool in await server.mcp.list_tools():
            assert tool.outputSchema is None, tool.name
