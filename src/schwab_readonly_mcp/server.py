import os

from mcp.server.fastmcp import FastMCP

from schwab_readonly_mcp import auth
from schwab_readonly_mcp.client import SchwabClient

mcp = FastMCP("schwab-readonly")


def _credentials() -> tuple[str, str]:
    # Read the OAuth client credentials from the environment. A missing/empty
    # value is an operator-configuration error, so raise a clear RuntimeError
    # (not a raw KeyError). Never log or echo the values — only their absence.
    client_id = os.environ.get("SCHWAB_CLIENT_ID")
    client_secret = os.environ.get("SCHWAB_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise RuntimeError(
            "SCHWAB_CLIENT_ID and SCHWAB_CLIENT_SECRET must be set; "
            "export them (from the Schwab Developer Portal)"
        )
    return client_id, client_secret


async def _client() -> SchwabClient:
    # One client per tool call: fetch a (possibly refreshed) access token, then
    # hand it to a fresh SchwabClient. Any scrubbed RuntimeError/ValueError from
    # auth/client propagates to FastMCP as a tool error — never caught here, so a
    # secret can't leak through a re-stringified message.
    client_id, client_secret = _credentials()
    token = await auth.get_access_token(client_id, client_secret)
    return SchwabClient(token)


# Each tool mirrors the SchwabClient method signature exactly (param names,
# types, defaults) so FastMCP's auto-generated input schema is correct, and
# returns the raw parsed JSON (-> object → no constraining output schema).


@mcp.tool()
async def list_accounts(include_positions: bool = True) -> object:
    return await (await _client()).list_accounts(include_positions)


@mcp.tool()
async def get_account(account_number: str, include_positions: bool = True) -> object:
    return await (await _client()).get_account(account_number, include_positions)


@mcp.tool()
async def get_transactions(
    account_number: str, start_date: str, end_date: str
) -> object:
    return await (await _client()).get_transactions(
        account_number, start_date, end_date
    )


@mcp.tool()
async def get_quotes(symbols: list[str]) -> object:
    return await (await _client()).get_quotes(symbols)


@mcp.tool()
async def get_price_history(
    symbol: str,
    period_type: str,
    period: int,
    frequency_type: str,
    frequency: int,
) -> object:
    return await (await _client()).get_price_history(
        symbol, period_type, period, frequency_type, frequency
    )
