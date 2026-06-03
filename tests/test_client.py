import httpx
import pytest
import respx

from schwab_readonly_mcp import client

ACCOUNTS_URL = f"{client.BASE_URL}/trader/v1/accounts"


def _bearer(req: httpx.Request) -> str:
    return req.headers["authorization"]


class TestListAccounts:
    @respx.mock
    async def test_includes_positions_by_default(self):
        body = [{"accountNumber": "123", "positions": []}]
        route = respx.get(ACCOUNTS_URL).mock(
            return_value=httpx.Response(200, json=body)
        )
        c = client.SchwabClient("TOKEN")
        result = await c.list_accounts()

        assert result == body
        assert route.called
        req = route.calls.last.request
        assert _bearer(req) == "Bearer TOKEN"
        assert req.url.path == "/trader/v1/accounts"
        assert req.url.params["fields"] == "positions"

    @respx.mock
    async def test_omits_fields_when_positions_excluded(self):
        route = respx.get(ACCOUNTS_URL).mock(
            return_value=httpx.Response(200, json=[])
        )
        c = client.SchwabClient("TOKEN")
        result = await c.list_accounts(include_positions=False)

        assert result == []
        req = route.calls.last.request
        assert "fields" not in req.url.params

    @respx.mock
    async def test_token_not_leaked_in_repr(self):
        c = client.SchwabClient("SUPERSECRET")
        assert "SUPERSECRET" not in repr(c)

    @respx.mock
    async def test_propagates_http_error(self):
        respx.get(ACCOUNTS_URL).mock(
            return_value=httpx.Response(500, json={"error": "boom"})
        )
        c = client.SchwabClient("TOKEN")
        with pytest.raises(httpx.HTTPStatusError):
            await c.list_accounts()


class TestGetAccount:
    @respx.mock
    async def test_includes_positions_by_default(self):
        body = {"accountNumber": "42", "positions": []}
        route = respx.get(f"{ACCOUNTS_URL}/42").mock(
            return_value=httpx.Response(200, json=body)
        )
        c = client.SchwabClient("TOKEN")
        result = await c.get_account("42")

        assert result == body
        req = route.calls.last.request
        assert _bearer(req) == "Bearer TOKEN"
        assert req.url.path == "/trader/v1/accounts/42"
        assert req.url.params["fields"] == "positions"

    @respx.mock
    async def test_omits_fields_when_positions_excluded(self):
        route = respx.get(f"{ACCOUNTS_URL}/42").mock(
            return_value=httpx.Response(200, json={"accountNumber": "42"})
        )
        c = client.SchwabClient("TOKEN")
        await c.get_account("42", include_positions=False)

        req = route.calls.last.request
        assert req.url.path == "/trader/v1/accounts/42"
        assert "fields" not in req.url.params
