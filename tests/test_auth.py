import base64
import dataclasses
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from schwab_readonly_mcp import auth


SERVICE = "schwab-readonly-mcp"


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


class TestStoreLoadTokens:
    def test_store_writes_three_keychain_entries(self):
        t = auth.TokenSet(
            access_token="A",
            refresh_token="R",
            access_expires_at=1700000000,
        )
        with patch.object(auth.keyring, "set_password") as setp:
            auth.store_tokens(t)
        calls = {c.args[1]: c.args[2] for c in setp.call_args_list}
        assert all(c.args[0] == SERVICE for c in setp.call_args_list)
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
            assert service == SERVICE
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


TOKEN_URL = "https://api.schwabapi.com/v1/oauth/token"


def _expected_basic_auth(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode()
    return "Basic " + base64.b64encode(raw).decode()


class TestExchangeCodeForTokens:
    @respx.mock
    async def test_returns_tokenset_and_sends_correct_request(self):
        route = respx.post(TOKEN_URL).mock(
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


class TestRefreshAccessToken:
    @respx.mock
    async def test_uses_new_refresh_token_when_returned(self):
        route = respx.post(TOKEN_URL).mock(
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
        respx.post(TOKEN_URL).mock(
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
