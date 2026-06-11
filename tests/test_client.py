from unittest.mock import patch

import httpx
import pytest
import respx
from conftest import assert_chain_carries_no, assert_hardened_client_kwargs

from schwab_readonly_mcp import client

ACCOUNTS_URL = f"{client.BASE_URL}/trader/v1/accounts"
ACCOUNT_NUMBERS_URL = f"{ACCOUNTS_URL}/accountNumbers"

# Schwab's full transaction-type enum, pinned LITERALLY (not imported from
# client) so a typo'd or dropped value in the client constant fails here.
ALL_TYPES = (
    "TRADE",
    "RECEIVE_AND_DELIVER",
    "DIVIDEND_OR_INTEREST",
    "ACH_RECEIPT",
    "ACH_DISBURSEMENT",
    "CASH_RECEIPT",
    "CASH_DISBURSEMENT",
    "ELECTRONIC_FUND",
    "WIRE_OUT",
    "WIRE_IN",
    "JOURNAL",
    "MEMORANDUM",
    "MARGIN_CALL",
    "MONEY_MARKET",
    "SMA_ADJUSTMENT",
)


def _bearer(req: httpx.Request) -> str:
    return req.headers["authorization"]


def _mock_account_numbers(mapping: object = None) -> respx.Route:
    # The per-account endpoints take Schwab's encrypted account hash, not the
    # plaintext number; this mocks the accountNumbers endpoint that maps one
    # to the other. Default mapping: plaintext "42" -> hash "HASH42".
    if mapping is None:
        mapping = [{"accountNumber": "42", "hashValue": "HASH42"}]
    return respx.get(ACCOUNT_NUMBERS_URL).mock(
        return_value=httpx.Response(200, json=mapping)
    )


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
        route = respx.get(ACCOUNTS_URL).mock(return_value=httpx.Response(200, json=[]))
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
        # HTTP errors surface as a scrubbed RuntimeError (the live, secret-bearing
        # httpx request must never escape) — the loud-fail contract is preserved.
        respx.get(ACCOUNTS_URL).mock(
            return_value=httpx.Response(status, json={"error": "boom"})
        )
        c = client.SchwabClient("TOKEN")
        with pytest.raises(RuntimeError, match=r"HTTP \d+"):
            await c.list_accounts()

    @respx.mock
    async def test_propagates_connection_error(self):
        # A transport failure must still propagate loudly, scrubbed to RuntimeError.
        respx.get(ACCOUNTS_URL).mock(side_effect=httpx.ConnectError("down"))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(RuntimeError):
            await c.list_accounts()

    @respx.mock
    async def test_propagates_timeout(self):
        respx.get(ACCOUNTS_URL).mock(side_effect=httpx.ReadTimeout("slow"))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(RuntimeError):
            await c.list_accounts()

    # Parametrized over both scrubbed_http_error branches (status error and
    # transport errors): invariant 3 covers "network failures", so a branch-
    # specific regression (e.g. a chained re-raise for TransportError only)
    # must fail here too.
    @pytest.mark.parametrize(
        "failure",
        [
            {"return_value": httpx.Response(401, json={"error": "boom"})},
            {"side_effect": httpx.ConnectError("down")},
            {"side_effect": httpx.ReadTimeout("slow")},
        ],
        ids=["http_401", "connect_error", "read_timeout"],
    )
    @respx.mock
    async def test_http_error_does_not_leak_bearer_token(self, failure):
        # The teeth: the raised error must not carry the Bearer token that the
        # secret-bearing request headers would expose — not only in str/repr, but
        # anywhere reachable by walking the exception chain (__context__/__cause__)
        # down to a retained httpx request's headers/body.
        respx.get(ACCOUNTS_URL).mock(**failure)
        c = client.SchwabClient("SUPERSECRET")
        with pytest.raises(RuntimeError) as excinfo:
            await c.list_accounts()
        assert_chain_carries_no(excinfo.value, "SUPERSECRET")

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
    async def test_non_json_body_error_carries_no_body_text(self):
        # A 200 with a truncated-yet-account-data-bearing body must not be
        # reachable from the raised error: json.JSONDecodeError retains the FULL
        # raw body on .doc, so it must be replaced and the chain severed, same
        # as httpx errors (parity with auth.py's token-endpoint scrub).
        respx.get(ACCOUNTS_URL).mock(
            return_value=httpx.Response(
                200,
                content=b'[{"accountNumber": "LEAKED_BODY_FRAGMENT',
                headers={"content-type": "application/json"},
            )
        )
        c = client.SchwabClient("TOKEN")
        with pytest.raises(ValueError) as excinfo:
            await c.list_accounts()
        assert_chain_carries_no(excinfo.value, "LEAKED_BODY_FRAGMENT")

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
        with pytest.raises(RuntimeError):
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
                respx.get(ACCOUNTS_URL).mock(return_value=httpx.Response(200, json=[]))
                await client.SchwabClient("TOKEN").list_accounts()

        assert_hardened_client_kwargs(captured)


class TestGetAccount:
    @respx.mock
    async def test_resolves_account_number_to_hash_with_positions(self):
        numbers = _mock_account_numbers()
        body = {"accountNumber": "42", "positions": []}
        route = respx.get(f"{ACCOUNTS_URL}/HASH42").mock(
            return_value=httpx.Response(200, json=body)
        )
        c = client.SchwabClient("TOKEN")
        result = await c.get_account("42")

        assert result == body
        assert numbers.called
        assert _bearer(numbers.calls.last.request) == "Bearer TOKEN"
        req = route.calls.last.request
        assert _bearer(req) == "Bearer TOKEN"
        # The per-account URL must carry the encrypted hash, never the
        # plaintext account number (Schwab 400s on the plaintext form).
        assert req.url.path == "/trader/v1/accounts/HASH42"
        assert req.url.params["fields"] == "positions"

    @respx.mock
    async def test_omits_fields_when_positions_excluded(self):
        _mock_account_numbers()
        route = respx.get(f"{ACCOUNTS_URL}/HASH42").mock(
            return_value=httpx.Response(200, json={"accountNumber": "42"})
        )
        c = client.SchwabClient("TOKEN")
        await c.get_account("42", include_positions=False)

        req = route.calls.last.request
        assert req.url.path == "/trader/v1/accounts/HASH42"
        assert "fields" not in req.url.params

    @respx.mock
    async def test_accepts_alphanumeric_account_number(self):
        # Account ids aren't guaranteed to be all-digits; alphanumerics must
        # pass _safe_account_number and resolve through the mapping like any
        # other value.
        acct = "ABC123def456"
        _mock_account_numbers([{"accountNumber": acct, "hashValue": "HASHX"}])
        route = respx.get(f"{ACCOUNTS_URL}/HASHX").mock(
            return_value=httpx.Response(200, json={"accountNumber": acct})
        )
        c = client.SchwabClient("TOKEN")
        await c.get_account(acct)
        assert route.called
        assert route.calls.last.request.url.path == "/trader/v1/accounts/HASHX"

    @respx.mock
    async def test_mapping_fetched_once_per_instance(self):
        # The accountNumbers mapping is cached on the client instance: three
        # per-account calls (across both methods) -> exactly one mapping fetch.
        numbers = _mock_account_numbers()
        respx.get(f"{ACCOUNTS_URL}/HASH42").mock(
            return_value=httpx.Response(200, json={})
        )
        respx.get(f"{ACCOUNTS_URL}/HASH42/transactions").mock(
            return_value=httpx.Response(200, json=[])
        )
        c = client.SchwabClient("TOKEN")
        await c.get_account("42")
        await c.get_account("42", include_positions=False)
        await c.get_transactions("42", "2024-01-01", "2024-03-31")
        assert numbers.call_count == 1

    @respx.mock
    async def test_unknown_account_number_raises_without_echo(self):
        _mock_account_numbers()
        # Catch-all AFTER the mapping route: any per-account request leaking
        # out for the unknown number would land here.
        catch = respx.route().mock(return_value=httpx.Response(200, json={}))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(
            ValueError, match="account_number not found among accessible accounts"
        ) as excinfo:
            await c.get_account("99999999")
        # Non-echoing contract (same as _safe_account_number): the supplied
        # value must not be reachable anywhere from the raised error, and the
        # chain must stay severed.
        assert_chain_carries_no(excinfo.value, "99999999")
        assert catch.called is False

    @respx.mock
    async def test_empty_mapping_is_unknown_account_not_malformed(self):
        # [] is a WELL-FORMED payload (a token with zero accessible trader
        # accounts), so the lookup must take the non-echoing unknown-account
        # branch — never the malformed-payload one.
        _mock_account_numbers([])
        catch = respx.route().mock(return_value=httpx.Response(200, json={}))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(
            ValueError, match="account_number not found among accessible accounts"
        ) as excinfo:
            await c.get_account("42")
        assert_chain_carries_no(excinfo.value, "42")
        assert catch.called is False

    @pytest.mark.parametrize(
        "mapping",
        [
            {"accountNumber": "42", "hashValue": "HASH42"},
            "HASH42",
            ["HASH42"],
            [{"hashValue": "HASH42"}],
            [{"accountNumber": "42"}],
            [{"accountNumber": 42, "hashValue": "HASH42"}],
            [{"accountNumber": "42", "hashValue": 7}],
            [{"accountNumber": "42", "hashValue": None}],
        ],
        ids=[
            "dict_not_list",
            "string_not_list",
            "list_of_strings",
            "missing_account_number",
            "missing_hash_value",
            "non_string_account_number",
            "non_string_hash_value",
            "none_hash_value",
        ],
    )
    @respx.mock
    async def test_malformed_mapping_raises_clean_value_error(self, mapping):
        # A malformed/hostile mapping body must surface as one clear
        # ValueError — never a KeyError/TypeError leaking payload structure —
        # and the per-account endpoint must not be hit.
        _mock_account_numbers(mapping)
        catch = respx.route().mock(return_value=httpx.Response(200, json={}))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(
            ValueError, match="malformed accountNumbers payload"
        ) as excinfo:
            await c.get_account("42")
        assert_chain_carries_no(excinfo.value)
        assert catch.called is False

    @pytest.mark.parametrize(
        "bad_hash",
        [
            "HA/SH42",
            "HASH42?evil=1",
            "../HASH42",
            "HASH42#f",
            "HA SH42",
            # pin the same denylist classes as the user-input path: percent,
            # backslash, and control chars (NUL is not isspace()).
            "HASH%2e42",
            "HASH\\42",
            "HASH\x0042",
            "",
            ".",
        ],
    )
    @respx.mock
    async def test_unsafe_hash_value_from_api_is_rejected(self, bad_hash):
        # Defense in depth: hashValue lands in a URL path segment too, so even
        # a value handed back by Schwab itself must pass the same denylist as
        # a user-supplied account number before interpolation.
        _mock_account_numbers([{"accountNumber": "42", "hashValue": bad_hash}])
        catch = respx.route().mock(return_value=httpx.Response(200, json={}))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(
            ValueError, match="malformed accountNumbers payload"
        ) as excinfo:
            await c.get_account("42")
        assert_chain_carries_no(excinfo.value)
        assert catch.called is False

    @respx.mock
    async def test_resolution_http_error_does_not_leak_bearer_token(self):
        # The mapping fetch goes through _get, so its failures must keep the
        # scrubbed-and-severed contract on this new code path too.
        respx.get(ACCOUNT_NUMBERS_URL).mock(
            return_value=httpx.Response(401, json={"error": "boom"})
        )
        c = client.SchwabClient("SUPERSECRET")
        with pytest.raises(RuntimeError, match=r"HTTP \d+") as excinfo:
            await c.get_account("42")
        assert_chain_carries_no(excinfo.value, "SUPERSECRET")

    @pytest.mark.parametrize(
        "bad",
        [
            "../../v1/oauth/token",
            "42?evil=1",
            "a/b",
            "a#b",
            "a%2e",
            "a\\b",
            "a b",
            # control chars: NUL and DEL are not isspace(), so they must be
            # caught by the explicit control-char rejection, not left to httpx.
            "a\x00b",
            "a\x7fb",
            ".",
            "",
        ],
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
    async def test_resolves_hash_and_sends_dates_with_default_types(self):
        numbers = _mock_account_numbers()
        body = [{"transactionId": 1}]
        route = respx.get(f"{ACCOUNTS_URL}/HASH42/transactions").mock(
            return_value=httpx.Response(200, json=body)
        )
        c = client.SchwabClient("TOKEN")
        result = await c.get_transactions(
            "42",
            "2024-01-01T00:00:00.000Z",
            "2024-03-31T23:59:59.999Z",
        )

        assert result == body
        assert numbers.called
        req = route.calls.last.request
        assert _bearer(req) == "Bearer TOKEN"
        assert req.url.path == "/trader/v1/accounts/HASH42/transactions"
        assert req.url.params["startDate"] == "2024-01-01T00:00:00.000Z"
        assert req.url.params["endDate"] == "2024-03-31T23:59:59.999Z"
        # types is NEVER omitted: the default is the full 15-value enum,
        # comma-joined (mirroring the reference client's behavior).
        assert req.url.params["types"] == ",".join(ALL_TYPES)
        assert len(ALL_TYPES) == 15

    @respx.mock
    async def test_explicit_types_passed_through(self):
        _mock_account_numbers()
        route = respx.get(f"{ACCOUNTS_URL}/HASH42/transactions").mock(
            return_value=httpx.Response(200, json=[])
        )
        c = client.SchwabClient("TOKEN")
        await c.get_transactions(
            "42", "2024-01-01", "2024-03-31", types="TRADE,DIVIDEND_OR_INTEREST"
        )

        req = route.calls.last.request
        assert req.url.params["types"] == "TRADE,DIVIDEND_OR_INTEREST"

    @respx.mock
    async def test_accepts_alphanumeric_account_number(self):
        # Account ids aren't guaranteed to be all-digits; alphanumerics must
        # pass _safe_account_number and resolve through the mapping.
        acct = "ABC123def456"
        _mock_account_numbers([{"accountNumber": acct, "hashValue": "HASHX"}])
        route = respx.get(f"{ACCOUNTS_URL}/HASHX/transactions").mock(
            return_value=httpx.Response(200, json=[])
        )
        c = client.SchwabClient("TOKEN")
        await c.get_transactions(acct, "2024-01-01", "2024-03-31")

        assert route.called
        req = route.calls.last.request
        assert _bearer(req) == "Bearer TOKEN"
        assert req.url.path == "/trader/v1/accounts/HASHX/transactions"
        assert req.url.params["startDate"] == "2024-01-01"
        assert req.url.params["endDate"] == "2024-03-31"

    @respx.mock
    async def test_unknown_account_number_raises_without_echo(self):
        _mock_account_numbers()
        catch = respx.route().mock(return_value=httpx.Response(200, json={}))
        c = client.SchwabClient("TOKEN")
        with pytest.raises(
            ValueError, match="account_number not found among accessible accounts"
        ) as excinfo:
            await c.get_transactions("99999999", "2024-01-01", "2024-03-31")
        assert_chain_carries_no(excinfo.value, "99999999")
        assert catch.called is False

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
        route = respx.get(QUOTES_URL).mock(return_value=httpx.Response(200, json=body))
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
        route = respx.get(QUOTES_URL).mock(return_value=httpx.Response(200, json={}))
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
