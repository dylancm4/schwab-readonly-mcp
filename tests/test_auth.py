import base64
import copy
import dataclasses
import pickle
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from schwab_readonly_mcp import auth


class TestTokenSet:
    def test_fields_accessible(self):
        t = auth.TokenSet(
            access_token=auth.Secret("a"),
            refresh_token=auth.Secret("r"),
            access_expires_at=1234567890,
        )
        assert t.access_token == auth.Secret("a")
        assert t.refresh_token == auth.Secret("r")
        assert t.access_expires_at == 1234567890

    def test_frozen(self):
        t = auth.TokenSet(
            access_token=auth.Secret("a"),
            refresh_token=auth.Secret("r"),
            access_expires_at=1,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            t.access_token = auth.Secret("b")

    def test_repr_redacts_tokens(self):
        t = auth.TokenSet(
            access_token=auth.Secret("SECRET_ACCESS"),
            refresh_token=auth.Secret("SECRET_REFRESH"),
            access_expires_at=1700000000,
        )
        r = repr(t)
        assert "SECRET_ACCESS" not in r
        assert "SECRET_REFRESH" not in r
        assert "<redacted>" in r
        assert "1700000000" in r  # the non-secret field is allowed

    def test_dataclasses_asdict_keeps_secrets_wrapped(self):
        t = auth.TokenSet(
            access_token=auth.Secret("SECRET_ACCESS"),
            refresh_token=auth.Secret("SECRET_REFRESH"),
            access_expires_at=1700000000,
        )
        d = dataclasses.asdict(t)
        assert isinstance(d["access_token"], auth.Secret)
        assert isinstance(d["refresh_token"], auth.Secret)
        assert "SECRET_ACCESS" not in repr(d)
        assert "SECRET_REFRESH" not in repr(d)
        assert "SECRET_ACCESS" not in str(d)
        assert "SECRET_REFRESH" not in str(d)

    def test_pickle_tokenset_redacts(self):
        t = auth.TokenSet(
            access_token=auth.Secret("SECRET_ACCESS"),
            refresh_token=auth.Secret("SECRET_REFRESH"),
            access_expires_at=1700000000,
        )
        data = pickle.dumps(t)
        assert b"SECRET_ACCESS" not in data
        assert b"SECRET_REFRESH" not in data
        restored = pickle.loads(data)
        assert isinstance(restored, auth.TokenSet)
        assert restored.access_token == auth.Secret("<redacted>")
        assert restored.refresh_token == auth.Secret("<redacted>")
        assert restored.access_expires_at == 1700000000


class TestSecret:
    def test_repr_redacts(self):
        s = auth.Secret("SUPERSECRET")
        assert "SUPERSECRET" not in repr(s)
        assert "<redacted>" in repr(s)

    def test_str_redacts(self):
        s = auth.Secret("SUPERSECRET")
        assert "SUPERSECRET" not in str(s)
        assert str(s) == "<redacted>"

    def test_format_redacts(self):
        s = auth.Secret("SUPERSECRET")
        assert f"{s}" == "<redacted>"
        assert format(s) == "<redacted>"
        assert format(s, ">20") == "<redacted>"

    def test_reveal_returns_raw(self):
        s = auth.Secret("SUPERSECRET")
        assert s.reveal() == "SUPERSECRET"

    # Pins the type-hint-only contract: Secret does NOT validate input.
    # Adding validation must be a conscious decision.
    def test_none_is_accepted_unchanged(self):
        s = auth.Secret(None)
        assert s.reveal() is None
        assert "None" not in str(s)
        assert "None" not in repr(s)
        assert "None" not in f"{s}"

    def test_pickle_roundtrip_redacts(self):
        s = auth.Secret("SUPERSECRET")
        data = pickle.dumps(s)
        assert b"SUPERSECRET" not in data
        restored = pickle.loads(data)
        assert isinstance(restored, auth.Secret)
        assert restored.reveal() == "<redacted>"

    def test_copy_and_deepcopy_redact(self):
        s = auth.Secret("REAL_VALUE")
        for fn in (copy.copy, copy.deepcopy):
            c = fn(s)
            assert isinstance(c, auth.Secret)
            assert c.reveal() == "<redacted>"
            assert "REAL_VALUE" not in repr(c)
            assert "REAL_VALUE" not in str(c)

    def test_vars_raises_no_dict(self):
        s = auth.Secret("SUPERSECRET")
        with pytest.raises(TypeError):
            vars(s)

    def test_equality(self):
        assert auth.Secret("A") == auth.Secret("A")
        assert auth.Secret("A") != auth.Secret("B")
        assert auth.Secret("A") != "A"
        assert auth.Secret("A") != 1

    def test_hashable(self):
        assert hash(auth.Secret("A")) == hash(auth.Secret("A"))
        d = {auth.Secret("A"): 1}
        assert d[auth.Secret("A")] == 1


class TestStoreLoadTokens:
    def test_store_writes_three_keychain_entries(self):
        t = auth.TokenSet(
            access_token=auth.Secret("A"),
            refresh_token=auth.Secret("R"),
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
            access_token=auth.Secret("A"),
            refresh_token=auth.Secret("R"),
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
            access_token=auth.Secret("AT"),
            refresh_token=auth.Secret("RT"),
            access_expires_at=1_700_000_000 + 1800,
        )
        assert route.called
        req = route.calls.last.request
        assert req.headers["authorization"] == _expected_basic_auth("cid", "csec")
        body = parse_qs(req.content.decode())
        assert body["grant_type"] == ["authorization_code"]
        assert body["code"] == ["THECODE"]
        assert body["redirect_uri"] == ["https://127.0.0.1:8443/cb"]

    @pytest.mark.parametrize("status", [400, 500, 503])
    @respx.mock
    async def test_propagates_http_error(self, status):
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(status, json={"error": "boom"})
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
        ids=["no_access_token", "no_refresh_token", "no_expires_in"],
    )
    @respx.mock
    async def test_raises_on_malformed_payload(self, payload):
        respx.post(auth.TOKEN_URL).mock(return_value=httpx.Response(200, json=payload))
        with pytest.raises(ValueError):
            await auth.exchange_code_for_tokens(
                "CODE", "cid", "csec", "https://127.0.0.1:8182"
            )

    @pytest.mark.parametrize(
        "payload",
        [
            {"access_token": None, "refresh_token": "RT", "expires_in": 1800},
            {"access_token": "", "refresh_token": "RT", "expires_in": 1800},
            {"access_token": "AT", "refresh_token": None, "expires_in": 1800},
            {"access_token": "AT", "refresh_token": "", "expires_in": 1800},
            {"access_token": "AT", "refresh_token": "RT", "expires_in": None},
        ],
        ids=[
            "null_access_token",
            "empty_access_token",
            "null_refresh_token",
            "empty_refresh_token",
            "null_expires_in",
        ],
    )
    @respx.mock
    async def test_raises_on_null_or_empty_payload_field(self, payload):
        respx.post(auth.TOKEN_URL).mock(return_value=httpx.Response(200, json=payload))
        with pytest.raises(ValueError, match="invalid"):
            await auth.exchange_code_for_tokens("CODE", "cid", "csec", "https://127.0.0.1:8182")

    @respx.mock
    async def test_raises_on_non_json_body(self):
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                content=b"<html>oops</html>",
                headers={"content-type": "text/html"},
            )
        )
        with pytest.raises(ValueError):
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
            access_token=auth.Secret("AT2"),
            refresh_token=auth.Secret("RT2"),
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

        assert result.refresh_token == auth.Secret("RT_OLD")
        assert result.access_token == auth.Secret("AT2")
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
        assert result.refresh_token == auth.Secret("RT_OLD")
        assert result.access_token == auth.Secret("AT2")

    @respx.mock
    async def test_reuses_input_refresh_token_when_response_has_null(self):
        # JSON null also exercises the `or` fallback, just like empty string
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "AT2", "refresh_token": None, "expires_in": 1800},
            )
        )
        result = await auth.refresh_access_token("RT_OLD", "cid", "csec")
        assert result.refresh_token == auth.Secret("RT_OLD")
        assert result.access_token == auth.Secret("AT2")

    @pytest.mark.parametrize("status", [400, 500, 503])
    @respx.mock
    async def test_propagates_http_error(self, status):
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(status, json={"error": "boom"})
        )
        with pytest.raises(httpx.HTTPStatusError):
            await auth.refresh_access_token("RT", "cid", "csec")

    @pytest.mark.parametrize(
        "payload",
        [
            {"refresh_token": "RT", "expires_in": 1800},  # missing access_token
            {"access_token": "AT", "refresh_token": "RT"},  # missing expires_in
        ],
        ids=["no_access_token", "no_expires_in"],
    )
    @respx.mock
    async def test_raises_on_malformed_payload(self, payload):
        respx.post(auth.TOKEN_URL).mock(return_value=httpx.Response(200, json=payload))
        with pytest.raises(ValueError):
            await auth.refresh_access_token("RT", "cid", "csec")

    @pytest.mark.parametrize(
        "payload",
        [
            {"access_token": None, "refresh_token": "RT", "expires_in": 1800},
            {"access_token": "", "refresh_token": "RT", "expires_in": 1800},
            {"access_token": "AT", "refresh_token": "RT", "expires_in": None},
            {"access_token": "AT", "refresh_token": 12345, "expires_in": 1800},
        ],
        ids=[
            "null_access_token",
            "empty_access_token",
            "null_expires_in",
            "wrong_type_refresh_token",
        ],
    )
    @respx.mock
    async def test_raises_on_null_or_invalid_payload_field(self, payload):
        respx.post(auth.TOKEN_URL).mock(return_value=httpx.Response(200, json=payload))
        with pytest.raises(ValueError, match="invalid"):
            await auth.refresh_access_token("RT_OLD", "cid", "csec")

    @respx.mock
    async def test_raises_on_non_json_body(self):
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                content=b"<html>oops</html>",
                headers={"content-type": "text/html"},
            )
        )
        with pytest.raises(ValueError):
            await auth.refresh_access_token("RT", "cid", "csec")


class TestGetAccessToken:
    NOW = 1_700_000_000.0

    def _loaded(self, expires_at: int) -> auth.TokenSet:
        return auth.TokenSet(
            access_token=auth.Secret("OLD"),
            refresh_token=auth.Secret("RT"),
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
            access_token=auth.Secret("NEW"),
            refresh_token=auth.Secret("RT2"),
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
