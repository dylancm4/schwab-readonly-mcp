from unittest.mock import patch

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

    async def test_token_not_leaked_in_repr_or_str(self):
        c = client.SchwabClient("SUPERSECRET")
        assert "SUPERSECRET" not in repr(c)
        assert "SUPERSECRET" not in str(c)
        # The teeth: if the token is stored as a raw str instead of Secret,
        # repr of the attribute itself would expose it.
        assert "SUPERSECRET" not in repr(c._access_token)

    @pytest.mark.parametrize("status", [400, 401, 404, 500, 503])
    @respx.mock
    async def test_propagates_http_error(self, status):
        respx.get(ACCOUNTS_URL).mock(
            return_value=httpx.Response(status, json={"error": "boom"})
        )
        c = client.SchwabClient("TOKEN")
        with pytest.raises(httpx.HTTPStatusError):
            await c.list_accounts()

    @respx.mock
    async def test_propagates_connection_error(self):
        # _get does no catching — a transport failure must propagate loudly.
        respx.get(ACCOUNTS_URL).mock(side_effect=httpx.ConnectError("down"))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(httpx.ConnectError):
            await c.list_accounts()

    @respx.mock
    async def test_propagates_timeout(self):
        respx.get(ACCOUNTS_URL).mock(side_effect=httpx.ReadTimeout("slow"))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(httpx.ReadTimeout):
            await c.list_accounts()

    @respx.mock
    async def test_raises_on_non_json_body(self):
        # A non-JSON 200 must loud-fail rather than silently return text.
        respx.get(ACCOUNTS_URL).mock(
            return_value=httpx.Response(
                200,
                content=b"<html>oops</html>",
                headers={"content-type": "text/html"},
            )
        )
        c = client.SchwabClient("TOKEN")
        with pytest.raises(ValueError):
            await c.list_accounts()

    @respx.mock
    async def test_does_not_follow_redirect_to_other_endpoint(self):
        # read-only invariant: a 3xx to a different route must NOT be followed.
        respx.get(ACCOUNTS_URL).mock(
            return_value=httpx.Response(
                302, headers={"Location": f"{client.BASE_URL}/v1/oauth/token"}
            )
        )
        target = respx.get(f"{client.BASE_URL}/v1/oauth/token").mock(
            return_value=httpx.Response(200, json={"leaked": True})
        )
        c = client.SchwabClient("TOKEN")
        with pytest.raises(httpx.HTTPStatusError):
            await c.list_accounts()
        assert target.called is False

    async def test_transport_hardening_construction_contract(self):
        # Lock the security-relevant AsyncClient kwargs against future refactors.
        real_cls = client.httpx.AsyncClient
        captured: dict[str, object] = {}

        def spy(*args, **kwargs):
            captured.update(kwargs)
            return real_cls(*args, **kwargs)

        with patch.object(client.httpx, "AsyncClient", side_effect=spy):
            with respx.mock:
                respx.get(ACCOUNTS_URL).mock(
                    return_value=httpx.Response(200, json=[])
                )
                await client.SchwabClient("TOKEN").list_accounts()

        assert captured["trust_env"] is False
        assert captured["follow_redirects"] is False
        assert isinstance(captured["timeout"], httpx.Timeout)


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

    @respx.mock
    async def test_accepts_alphanumeric_hash_account_number(self):
        # Schwab's real account id is an encrypted hash; alphanumerics must pass.
        acct = "ABC123def456"
        route = respx.get(f"{ACCOUNTS_URL}/{acct}").mock(
            return_value=httpx.Response(200, json={"accountNumber": acct})
        )
        c = client.SchwabClient("TOKEN")
        await c.get_account(acct)
        assert route.called
        assert route.calls.last.request.url.path == f"/trader/v1/accounts/{acct}"

    @pytest.mark.parametrize(
        "bad",
        ["../../v1/oauth/token", "42?evil=1", "a/b", "a#b", "a%2e", "a\\b", "a b", ""],
    )
    @respx.mock
    async def test_rejects_path_injection_account_number(self, bad):
        # Catch-all so any leaked request would be observable, then assert none.
        catch = respx.route().mock(return_value=httpx.Response(200, json={}))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(ValueError, match="invalid account_number"):
            await c.get_account(bad)
        assert catch.called is False


class TestGetTransactions:
    @respx.mock
    async def test_sends_date_params_and_returns_body(self):
        body = [{"transactionId": 1}]
        route = respx.get(f"{ACCOUNTS_URL}/42/transactions").mock(
            return_value=httpx.Response(200, json=body)
        )
        c = client.SchwabClient("TOKEN")
        result = await c.get_transactions(
            "42",
            "2024-01-01T00:00:00.000Z",
            "2024-03-31T23:59:59.999Z",
        )

        assert result == body
        req = route.calls.last.request
        assert _bearer(req) == "Bearer TOKEN"
        assert req.url.path == "/trader/v1/accounts/42/transactions"
        assert req.url.params["startDate"] == "2024-01-01T00:00:00.000Z"
        assert req.url.params["endDate"] == "2024-03-31T23:59:59.999Z"

    @respx.mock
    async def test_rejects_path_injection_account_number(self):
        catch = respx.route().mock(return_value=httpx.Response(200, json={}))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(ValueError, match="invalid account_number"):
            await c.get_transactions("a/b", "2024-01-01", "2024-03-31")
        assert catch.called is False


QUOTES_URL = f"{client.BASE_URL}/marketdata/v1/quotes"


class TestGetQuotes:
    @respx.mock
    async def test_joins_multiple_symbols_with_comma(self):
        body = {"AAPL": {}, "MSFT": {}}
        route = respx.get(QUOTES_URL).mock(
            return_value=httpx.Response(200, json=body)
        )
        c = client.SchwabClient("TOKEN")
        result = await c.get_quotes(["AAPL", "MSFT"])

        assert result == body
        req = route.calls.last.request
        assert _bearer(req) == "Bearer TOKEN"
        assert req.url.path == "/marketdata/v1/quotes"
        assert req.url.params["symbols"] == "AAPL,MSFT"

    @respx.mock
    async def test_single_symbol(self):
        route = respx.get(QUOTES_URL).mock(
            return_value=httpx.Response(200, json={"AAPL": {}})
        )
        c = client.SchwabClient("TOKEN")
        await c.get_quotes(["AAPL"])

        req = route.calls.last.request
        assert req.url.params["symbols"] == "AAPL"

    @respx.mock
    async def test_empty_symbols_sends_empty_param(self):
        route = respx.get(QUOTES_URL).mock(
            return_value=httpx.Response(200, json={})
        )
        c = client.SchwabClient("TOKEN")
        result = await c.get_quotes([])

        assert result == {}
        req = route.calls.last.request
        assert req.url.params["symbols"] == ""


PRICE_HISTORY_URL = f"{client.BASE_URL}/marketdata/v1/pricehistory"


class TestGetPriceHistory:
    @respx.mock
    async def test_maps_snake_case_args_to_camel_case_params(self):
        body = {"symbol": "AAPL", "candles": []}
        route = respx.get(PRICE_HISTORY_URL).mock(
            return_value=httpx.Response(200, json=body)
        )
        c = client.SchwabClient("TOKEN")
        result = await c.get_price_history(
            symbol="AAPL",
            period_type="month",
            period=1,
            frequency_type="daily",
            frequency=1,
        )

        assert result == body
        req = route.calls.last.request
        assert _bearer(req) == "Bearer TOKEN"
        assert req.url.path == "/marketdata/v1/pricehistory"
        assert req.url.params["symbol"] == "AAPL"
        assert req.url.params["periodType"] == "month"
        assert req.url.params["period"] == "1"
        assert req.url.params["frequencyType"] == "daily"
        assert req.url.params["frequency"] == "1"
