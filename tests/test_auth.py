import base64
import dataclasses
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from schwab_readonly_mcp import auth


class TestTokenSet:
    def test_fields_accessible(self):
        t = auth.TokenSet(
            access_token="a",
            refresh_token="r",
            access_expires_at=1234567890,
        )
        assert t.access_token == "a"
        assert t.refresh_token == "r"
        assert t.access_expires_at == 1234567890

    def test_frozen(self):
        t = auth.TokenSet(
            access_token="a",
            refresh_token="r",
            access_expires_at=1,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            t.access_token = "b"

    def test_repr_redacts_tokens(self):
        t = auth.TokenSet(
            access_token="SECRET_ACCESS",
            refresh_token="SECRET_REFRESH",
            access_expires_at=1700000000,
        )
        r = repr(t)
        assert "SECRET_ACCESS" not in r
        assert "SECRET_REFRESH" not in r
        assert "<redacted>" in r
        assert "1700000000" in r  # the non-secret field is allowed


class TestStoreLoadTokens:
    def test_store_writes_three_keychain_entries(self):
        t = auth.TokenSet(
            access_token="A",
            refresh_token="R",
            access_expires_at=1700000000,
        )
        with patch.object(auth.keyring, "set_password") as setp:
            auth.store_tokens(t)
        calls = {}
        for call in setp.call_args_list:
            service, key, value = call.args
            assert service == auth.SERVICE
            calls[key] = value
        assert calls == {
            "access_token": "A",
            "refresh_token": "R",
            "access_expires_at": "1700000000",
        }

    def test_load_round_trips(self):
        stored = {
            "access_token": "A",
            "refresh_token": "R",
            "access_expires_at": "1700000000",
        }

        def fake_get(service, key):
            assert service == auth.SERVICE
            return stored.get(key)

        with patch.object(auth.keyring, "get_password", side_effect=fake_get):
            loaded = auth.load_tokens()
        assert loaded == auth.TokenSet(
            access_token="A",
            refresh_token="R",
            access_expires_at=1700000000,
        )

    @pytest.mark.parametrize(
        "missing", ["access_token", "refresh_token", "access_expires_at"]
    )
    def test_load_raises_when_any_field_missing(self, missing):
        stored = {
            "access_token": "A",
            "refresh_token": "R",
            "access_expires_at": "1700000000",
        }
        stored[missing] = None

        with patch.object(
            auth.keyring,
            "get_password",
            side_effect=lambda s, k: stored.get(k),
        ):
            with pytest.raises(RuntimeError, match="No tokens stored"):
                auth.load_tokens()


def _expected_basic_auth(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode()
    return "Basic " + base64.b64encode(raw).decode()


class TestExchangeCodeForTokens:
    @respx.mock
    async def test_returns_tokenset_and_sends_correct_request(self):
        route = respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "AT",
                    "refresh_token": "RT",
                    "expires_in": 1800,
                    "token_type": "Bearer",
                },
            )
        )
        with patch.object(auth.time, "time", return_value=1_700_000_000.0):
            result = await auth.exchange_code_for_tokens(
                code="THECODE",
                client_id="cid",
                client_secret="csec",
                redirect_uri="https://127.0.0.1:8443/cb",
            )

        assert result == auth.TokenSet(
            access_token="AT",
            refresh_token="RT",
            access_expires_at=1_700_000_000 + 1800,
        )
        assert route.called
        req = route.calls.last.request
        assert req.headers["authorization"] == _expected_basic_auth("cid", "csec")
        body = parse_qs(req.content.decode())
        assert body["grant_type"] == ["authorization_code"]
        assert body["code"] == ["THECODE"]
        assert body["redirect_uri"] == ["https://127.0.0.1:8443/cb"]

    @respx.mock
    async def test_propagates_http_error(self):
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_request"})
        )
        with pytest.raises(httpx.HTTPStatusError):
            await auth.exchange_code_for_tokens(
                "CODE", "cid", "csec", "https://127.0.0.1:8182"
            )

    @pytest.mark.parametrize(
        "payload",
        [
            {"refresh_token": "RT", "expires_in": 1800},  # missing access_token
            {"access_token": "AT", "expires_in": 1800},   # missing refresh_token
            {"access_token": "AT", "refresh_token": "RT"},  # missing expires_in
        ],
    )
    @respx.mock
    async def test_raises_on_malformed_payload(self, payload):
        respx.post(auth.TOKEN_URL).mock(return_value=httpx.Response(200, json=payload))
        with pytest.raises(KeyError):
            await auth.exchange_code_for_tokens(
                "CODE", "cid", "csec", "https://127.0.0.1:8182"
            )

    @respx.mock
    async def test_raises_on_non_json_body(self):
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                content=b"<html>oops</html>",
                headers={"content-type": "text/html"},
            )
        )
        with pytest.raises(Exception):  # httpx wraps json.JSONDecodeError; be lenient on the exact type
            await auth.exchange_code_for_tokens(
                "CODE", "cid", "csec", "https://127.0.0.1:8182"
            )


class TestRefreshAccessToken:
    @respx.mock
    async def test_uses_new_refresh_token_when_returned(self):
        route = respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "AT2",
                    "refresh_token": "RT2",
                    "expires_in": 1800,
                },
            )
        )
        with patch.object(auth.time, "time", return_value=1_700_000_000.0):
            result = await auth.refresh_access_token(
                refresh_token="RT_OLD",
                client_id="cid",
                client_secret="csec",
            )

        assert result == auth.TokenSet(
            access_token="AT2",
            refresh_token="RT2",
            access_expires_at=1_700_000_000 + 1800,
        )
        req = route.calls.last.request
        assert req.headers["authorization"] == _expected_basic_auth("cid", "csec")
        body = parse_qs(req.content.decode())
        assert body["grant_type"] == ["refresh_token"]
        assert body["refresh_token"] == ["RT_OLD"]

    @respx.mock
    async def test_reuses_input_refresh_token_when_response_omits_it(self):
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "AT2", "expires_in": 1800},
            )
        )
        with patch.object(auth.time, "time", return_value=1_700_000_000.0):
            result = await auth.refresh_access_token(
                refresh_token="RT_OLD",
                client_id="cid",
                client_secret="csec",
            )

        assert result.refresh_token == "RT_OLD"
        assert result.access_token == "AT2"
        assert result.access_expires_at == 1_700_000_000 + 1800

    @respx.mock
    async def test_reuses_input_refresh_token_when_response_has_empty_string(self):
        # Schwab "ought to omit" but the protocol cousin could send "" — must not store ""
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "AT2", "refresh_token": "", "expires_in": 1800},
            )
        )
        result = await auth.refresh_access_token("RT_OLD", "cid", "csec")
        assert result.refresh_token == "RT_OLD"
        assert result.access_token == "AT2"

    @respx.mock
    async def test_propagates_http_error(self):
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_grant"})
        )
        with pytest.raises(httpx.HTTPStatusError):
            await auth.refresh_access_token("RT", "cid", "csec")

    @pytest.mark.parametrize(
        "payload",
        [
            {"refresh_token": "RT", "expires_in": 1800},  # missing access_token
            {"access_token": "AT", "refresh_token": "RT"},  # missing expires_in
        ],
    )
    @respx.mock
    async def test_raises_on_malformed_payload(self, payload):
        respx.post(auth.TOKEN_URL).mock(return_value=httpx.Response(200, json=payload))
        with pytest.raises(KeyError):
            await auth.refresh_access_token("RT", "cid", "csec")

    @respx.mock
    async def test_raises_on_non_json_body(self):
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                content=b"<html>oops</html>",
                headers={"content-type": "text/html"},
            )
        )
        with pytest.raises(Exception):  # httpx wraps json.JSONDecodeError; be lenient on the exact type
            await auth.refresh_access_token("RT", "cid", "csec")


class TestGetAccessToken:
    NOW = 1_700_000_000.0

    def _loaded(self, expires_at: int) -> auth.TokenSet:
        return auth.TokenSet(
            access_token="OLD",
            refresh_token="RT",
            access_expires_at=expires_at,
        )

    async def test_returns_loaded_when_fresh(self):
        loaded = self._loaded(int(self.NOW) + 100)
        with (
            patch.object(auth, "load_tokens", return_value=loaded),
            patch.object(auth, "refresh_access_token", new_callable=AsyncMock) as ref,
            patch.object(auth, "store_tokens") as store,
            patch.object(auth.time, "time", return_value=self.NOW),
        ):
            result = await auth.get_access_token("cid", "csec")

        assert result == "OLD"
        ref.assert_not_called()
        store.assert_not_called()

    async def test_does_not_refresh_at_exact_threshold(self):
        # delta = 30 → not < 30 → no refresh
        loaded = self._loaded(int(self.NOW) + 30)
        with (
            patch.object(auth, "load_tokens", return_value=loaded),
            patch.object(auth, "refresh_access_token", new=AsyncMock()) as ref,
            patch.object(auth, "store_tokens") as store,
            patch.object(auth.time, "time", return_value=self.NOW),
        ):
            result = await auth.get_access_token("cid", "csec")
        assert result == "OLD"
        ref.assert_not_awaited()
        store.assert_not_called()

    @pytest.mark.parametrize("delta", [29, -100])
    async def test_refreshes_when_at_or_past_threshold(self, delta):
        loaded = self._loaded(int(self.NOW) + delta)
        refreshed = auth.TokenSet(
            access_token="NEW",
            refresh_token="RT2",
            access_expires_at=int(self.NOW) + 1800,
        )
        ref_mock = AsyncMock(return_value=refreshed)
        with (
            patch.object(auth, "load_tokens", return_value=loaded),
            patch.object(auth, "refresh_access_token", ref_mock),
            patch.object(auth, "store_tokens") as store,
            patch.object(auth.time, "time", return_value=self.NOW),
        ):
            result = await auth.get_access_token("cid", "csec")

        assert result == "NEW"
        ref_mock.assert_awaited_once_with("RT", "cid", "csec")
        store.assert_called_once_with(refreshed)
