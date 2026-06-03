import httpx

from schwab_readonly_mcp.auth import Secret

BASE_URL = "https://api.schwabapi.com"


class SchwabClient:
    def __init__(self, access_token: str) -> None:
        self._access_token = Secret(access_token)

    async def _get(
        self, path: str, params: dict[str, str | int] | None = None
    ) -> object:
        async with httpx.AsyncClient(
            trust_env=False,
            timeout=httpx.Timeout(10.0, connect=5.0),
        ) as client:
            response = await client.get(
                f"{BASE_URL}{path}",
                params=params,
                headers={"Authorization": f"Bearer {self._access_token.reveal()}"},
            )
            response.raise_for_status()
            return response.json()

    async def list_accounts(self, include_positions: bool = True) -> object:
        params = {"fields": "positions"} if include_positions else None
        return await self._get("/trader/v1/accounts", params)

    async def get_account(
        self, account_number: str, include_positions: bool = True
    ) -> object:
        params = {"fields": "positions"} if include_positions else None
        return await self._get(f"/trader/v1/accounts/{account_number}", params)

    async def get_transactions(
        self, account_number: str, start_date: str, end_date: str
    ) -> object:
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
