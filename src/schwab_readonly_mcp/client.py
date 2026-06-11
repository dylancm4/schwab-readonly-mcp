import httpx

from schwab_readonly_mcp.auth import Secret, scrubbed_http_error

BASE_URL = "https://api.schwabapi.com"


def _safe_account_number(value: str) -> str:
    # read-only safety: account_number is interpolated into the URL path,
    # so reject anything that could traverse to another endpoint or inject a query.
    # Control chars (C0 incl. NUL, and DEL) are rejected here explicitly — NUL/DEL
    # are not isspace() and would otherwise slip past this denylist, leaving the
    # guarantee resting on downstream httpx behavior instead of the auditable check.
    # This denylist is sufficient only because the value lands in a path *segment*
    # behind the fixed BASE_URL host+scheme and httpx percent-encodes exotic path
    # bytes; revisit if the URL is ever built differently or the value moves to the host.
    if (
        not value
        or any(c.isspace() for c in value)
        or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
        or any(c in value for c in "/\\?#%")
        or ".." in value
        or value == "."
    ):
        raise ValueError("invalid account_number")
    return value


class SchwabClient:
    def __init__(self, access_token: str) -> None:
        self._access_token = Secret(access_token)

    async def _get(
        self, path: str, params: dict[str, str | int] | None = None
    ) -> object:
        # int param values (e.g. period, frequency) are serialized to strings
        # on the wire by httpx, so callers may pass ints freely.
        async with httpx.AsyncClient(
            trust_env=False,
            timeout=httpx.Timeout(10.0, connect=5.0),
            # read-only — never auto-follow a redirect to another endpoint.
            follow_redirects=False,
        ) as client:
            try:
                response = await client.get(
                    f"{BASE_URL}{path}",
                    params=params,
                    headers={"Authorization": f"Bearer {self._access_token.reveal()}"},
                )
                response.raise_for_status()
            except httpx.HTTPError as e:
                # Build the scrubbed error here, but raise it OUTSIDE the except
                # block: with no active exception at the raise site, its
                # __context__ stays None, so the live secret-bearing httpx
                # request can't be reached by a crash reporter walking the chain.
                error = scrubbed_http_error(e)
            else:
                try:
                    payload = response.json()
                except ValueError:
                    # json.JSONDecodeError retains the FULL raw body on .doc,
                    # which here can carry account data. Replace it; the raise
                    # below (outside the except) keeps the chain severed.
                    error = ValueError("Schwab API returned non-JSON body")
                else:
                    return payload
        raise error

    async def list_accounts(self, include_positions: bool = True) -> object:
        params = {"fields": "positions"} if include_positions else None
        return await self._get("/trader/v1/accounts", params)

    async def get_account(
        self, account_number: str, include_positions: bool = True
    ) -> object:
        account_number = _safe_account_number(account_number)
        params = {"fields": "positions"} if include_positions else None
        return await self._get(f"/trader/v1/accounts/{account_number}", params)

    async def get_transactions(
        self, account_number: str, start_date: str, end_date: str
    ) -> object:
        account_number = _safe_account_number(account_number)
        return await self._get(
            f"/trader/v1/accounts/{account_number}/transactions",
            {"startDate": start_date, "endDate": end_date},
        )

    async def get_quotes(self, symbols: list[str]) -> object:
        return await self._get(
            "/marketdata/v1/quotes",
            {"symbols": ",".join(symbols)},
        )

    async def get_price_history(
        self,
        symbol: str,
        period_type: str,
        period: int,
        frequency_type: str,
        frequency: int,
    ) -> object:
        return await self._get(
            "/marketdata/v1/pricehistory",
            {
                "symbol": symbol,
                "periodType": period_type,
                "period": period,
                "frequencyType": frequency_type,
                "frequency": frequency,
            },
        )
