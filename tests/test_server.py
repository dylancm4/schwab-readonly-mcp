from schwab_readonly_mcp import server

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
