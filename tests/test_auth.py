import asyncio
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

    def test_getstate_does_not_leak_raw_value(self):
        # __reduce__ already governs pickle/copy (both redact), but a direct
        # __getstate__() call on a __slots__ object would otherwise expose the
        # raw value. Redact this introspection path too.
        s = auth.Secret("SUPERSECRET")
        assert "SUPERSECRET" not in repr(s.__getstate__())

    def test_double_wrap_unwraps_to_raw_string(self):
        # Secret(Secret(x)) must reveal the raw string, not a nested Secret,
        # so a stray double-wrap can't make reveal() return a Secret.
        s = auth.Secret(auth.Secret("SUPERSECRET"))
        assert s.reveal() == "SUPERSECRET"
        assert "SUPERSECRET" not in repr(s)
        assert "SUPERSECRET" not in str(s)


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
        # access_expires_at MUST be written LAST (deliberate fail-safe: a partial
        # write leaves a missing/stale expiry, never a fresh token + stale expiry).
        assert setp.call_args_list[-1].args[1] == "access_expires_at"

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

    def test_load_raises_clear_error_on_corrupt_expires_at(self):
        stored = {
            "access_token": "A",
            "refresh_token": "R",
            "access_expires_at": "not-a-number",
        }

        with patch.object(
            auth.keyring,
            "get_password",
            side_effect=lambda s, k: stored.get(k),
        ):
            with pytest.raises(RuntimeError, match="corrupt"):
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
        with pytest.raises(RuntimeError, match=r"HTTP \d+"):
            await auth.exchange_code_for_tokens(
                "CODE", "cid", "csec", "https://127.0.0.1:8182"
            )

    @respx.mock
    async def test_propagates_connection_error(self):
        respx.post(auth.TOKEN_URL).mock(side_effect=httpx.ConnectError("down"))
        with pytest.raises(RuntimeError):
            await auth.exchange_code_for_tokens(
                "CODE", "cid", "csec", "https://127.0.0.1:8182"
            )

    @respx.mock
    async def test_propagates_timeout(self):
        respx.post(auth.TOKEN_URL).mock(side_effect=httpx.ReadTimeout("slow"))
        with pytest.raises(RuntimeError):
            await auth.exchange_code_for_tokens(
                "CODE", "cid", "csec", "https://127.0.0.1:8182"
            )

    @respx.mock
    async def test_http_error_does_not_leak_credentials_or_code(self):
        # The teeth: the raised error must not carry the Basic credentials or the
        # authorization code that the secret-bearing request would expose — not
        # only in str/repr, but anywhere reachable by walking the exception chain
        # (__context__/__cause__) down to a retained httpx request's headers/body.
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "boom"})
        )
        with pytest.raises(RuntimeError) as excinfo:
            await auth.exchange_code_for_tokens(
                "THECODE", "cid", "SUPERSECRET", "https://127.0.0.1:8182"
            )
        exc = excinfo.value
        assert exc.__context__ is None
        assert exc.__cause__ is None
        seen, cur = [], exc
        while cur is not None and cur not in seen:
            seen.append(cur)
            text = repr(cur) + str(cur)
            req = getattr(cur, "request", None)
            if req is not None:
                text += repr(dict(req.headers)) + req.content.decode("utf-8", "replace")
            for leaked in ("SUPERSECRET", "THECODE"):
                assert leaked not in text
            cur = cur.__context__ or cur.__cause__

    # Kept distinct from test_raises_on_invalid_payload_field: both end in a
    # ValueError from _require_str (access_token/refresh_token) or _require_int
    # (expires_in), but document missing-key vs present-but-invalid as separate
    # wire-shape concerns.
    @pytest.mark.parametrize(
        "payload",
        [
            {"refresh_token": "RT", "expires_in": 1800},  # missing access_token
            {"access_token": "AT", "expires_in": 1800},  # missing refresh_token
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
            {"access_token": "AT", "refresh_token": "RT", "expires_in": True},
            {"access_token": "AT", "refresh_token": "RT", "expires_in": 0},
        ],
        ids=[
            "null_access_token",
            "empty_access_token",
            "null_refresh_token",
            "empty_refresh_token",
            "null_expires_in",
            "bool_expires_in",
            "zero_expires_in",
        ],
    )
    @respx.mock
    async def test_raises_on_invalid_payload_field(self, payload):
        respx.post(auth.TOKEN_URL).mock(return_value=httpx.Response(200, json=payload))
        with pytest.raises(ValueError, match="invalid"):
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
        with pytest.raises(RuntimeError, match=r"HTTP \d+"):
            await auth.refresh_access_token("RT", "cid", "csec")

    @respx.mock
    async def test_propagates_connection_error(self):
        respx.post(auth.TOKEN_URL).mock(side_effect=httpx.ConnectError("down"))
        with pytest.raises(RuntimeError):
            await auth.refresh_access_token("RT", "cid", "csec")

    @respx.mock
    async def test_propagates_timeout(self):
        respx.post(auth.TOKEN_URL).mock(side_effect=httpx.ReadTimeout("slow"))
        with pytest.raises(RuntimeError):
            await auth.refresh_access_token("RT", "cid", "csec")

    @respx.mock
    async def test_http_error_does_not_leak_credentials_or_refresh_token(self):
        # The teeth: the raised error must not carry the Basic credentials or the
        # refresh token that the secret-bearing request would expose — not only in
        # str/repr, but anywhere reachable by walking the exception chain
        # (__context__/__cause__) down to a retained httpx request's headers/body.
        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "boom"})
        )
        with pytest.raises(RuntimeError) as excinfo:
            await auth.refresh_access_token("RT_SUPERSECRET", "cid", "CSEC_SECRET")
        exc = excinfo.value
        assert exc.__context__ is None
        assert exc.__cause__ is None
        seen, cur = [], exc
        while cur is not None and cur not in seen:
            seen.append(cur)
            text = repr(cur) + str(cur)
            req = getattr(cur, "request", None)
            if req is not None:
                text += repr(dict(req.headers)) + req.content.decode("utf-8", "replace")
            for leaked in ("RT_SUPERSECRET", "CSEC_SECRET"):
                assert leaked not in text
            cur = cur.__context__ or cur.__cause__

    # Kept distinct from test_raises_on_invalid_payload_field: both end in a
    # ValueError from _require_str (access_token/refresh_token) or _require_int
    # (expires_in), but document missing-key vs present-but-invalid as separate
    # wire-shape concerns.
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
            {"access_token": "AT", "refresh_token": "RT", "expires_in": True},
            {"access_token": "AT", "refresh_token": "RT", "expires_in": 0},
        ],
        ids=[
            "null_access_token",
            "empty_access_token",
            "null_expires_in",
            "wrong_type_refresh_token",
            "bool_expires_in",
            "zero_expires_in",
        ],
    )
    @respx.mock
    async def test_raises_on_invalid_payload_field(self, payload):
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
            patch.object(auth, "load_tokens", return_value=loaded) as load,
            patch.object(auth, "refresh_access_token", new_callable=AsyncMock) as ref,
            patch.object(auth, "store_tokens") as store,
            patch.object(auth.time, "time", return_value=self.NOW),
        ):
            result = await auth.get_access_token("cid", "csec")

        assert result == "OLD"
        # Fast path: the pre-lock check returns the stored token, so we never
        # re-load inside the lock.
        load.assert_called_once()
        ref.assert_not_called()
        store.assert_not_called()

    async def test_does_not_refresh_at_exact_threshold(self):
        # delta = 30 → 30 >= REFRESH_SKEW_SECONDS → fresh → no refresh
        loaded = self._loaded(int(self.NOW) + 30)
        with (
            patch.object(auth, "load_tokens", return_value=loaded) as load,
            patch.object(auth, "refresh_access_token", new=AsyncMock()) as ref,
            patch.object(auth, "store_tokens") as store,
            patch.object(auth.time, "time", return_value=self.NOW),
        ):
            result = await auth.get_access_token("cid", "csec")
        assert result == "OLD"
        load.assert_called_once()
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
            patch.object(auth, "load_tokens", return_value=loaded) as load,
            patch.object(auth, "refresh_access_token", ref_mock),
            patch.object(auth, "store_tokens") as store,
            patch.object(auth.time, "time", return_value=self.NOW),
        ):
            result = await auth.get_access_token("cid", "csec")

        assert result == "NEW"
        # Refresh path double-loads by design: once before the lock, then again
        # inside it (another coroutine may have refreshed while we waited).
        assert load.call_count == 2
        ref_mock.assert_awaited_once_with("RT", "cid", "csec")
        store.assert_called_once_with(refreshed)

    async def test_propagates_refresh_failure_without_storing(self):
        # If refresh fails (e.g. a scrubbed RuntimeError from a network error),
        # the failure must propagate and NO tokens get stored — never silently
        # hand back the already-expired access token.
        loaded = self._loaded(int(self.NOW) - 100)
        ref_mock = AsyncMock(side_effect=RuntimeError("Schwab API returned HTTP 400"))
        with (
            patch.object(auth, "load_tokens", return_value=loaded) as load,
            patch.object(auth, "refresh_access_token", ref_mock),
            patch.object(auth, "store_tokens") as store,
            patch.object(auth.time, "time", return_value=self.NOW),
        ):
            with pytest.raises(RuntimeError, match="HTTP 400"):
                await auth.get_access_token("cid", "csec")

        # Re-load inside the lock confirmed still-expired, then refresh failed.
        assert load.call_count == 2
        ref_mock.assert_awaited_once_with("RT", "cid", "csec")
        store.assert_not_called()

    @respx.mock
    async def test_concurrent_near_expiry_refreshes_exactly_once(self):
        # FastMCP serves tool calls concurrently and Schwab ROTATES the refresh
        # token on use, so two near-expiry get_access_token calls racing to
        # refresh would invalidate each other. The double-checked lock must let
        # exactly ONE refresh happen; the loser re-reads the freshly-stored token.
        store = {
            "access_token": "OLD",
            "refresh_token": "RT",
            "access_expires_at": str(int(self.NOW) - 100),  # already expired
        }

        # Dict-backed keyring fake: set_password writes, get_password reads the
        # SAME store, so a refresh by one coroutine is visible to the other.
        def fake_set(service, key, value):
            assert service == auth.SERVICE
            store[key] = value

        def fake_get(service, key):
            assert service == auth.SERVICE
            return store.get(key)

        # The refresh handler yields control (await) BEFORE responding, so the
        # second caller is guaranteed to run while the first is mid-refresh. A
        # plain return_value mock resolves without yielding, letting caller #1
        # finish its whole refresh first — that would mask a missing lock. This
        # yield is what gives the test teeth: without the lock, both callers pass
        # the in-lock re-check and route.call_count would be 2.
        async def slow_refresh(request):
            await asyncio.sleep(0)
            return httpx.Response(
                200,
                json={
                    "access_token": "NEW",
                    "refresh_token": "RT2",
                    "expires_in": 1800,  # far-future relative to NOW
                },
            )

        route = respx.post(auth.TOKEN_URL).mock(side_effect=slow_refresh)

        with (
            patch.object(auth.keyring, "set_password", side_effect=fake_set),
            patch.object(auth.keyring, "get_password", side_effect=fake_get),
            patch.object(auth.time, "time", return_value=self.NOW),
        ):
            results = await asyncio.gather(
                auth.get_access_token("cid", "csec"),
                auth.get_access_token("cid", "csec"),
            )

        # Exactly one network refresh despite two concurrent callers.
        assert route.call_count == 1
        # Both callers return the SAME new access token.
        assert results == ["NEW", "NEW"]
        # The rotated tokens were persisted for the next call.
        assert store["access_token"] == "NEW"
        assert store["refresh_token"] == "RT2"
        assert store["access_expires_at"] == str(int(self.NOW) + 1800)

    @respx.mock
    async def test_concurrent_refresh_failure_releases_lock_for_waiter(self):
        # Deadlock-guard regression. `async with _refresh_lock` releases the lock
        # structurally even when the in-lock refresh RAISES — but a future refactor
        # to manual acquire/release could regress this with no other test failing.
        # Here caller A's refresh fails (HTTP 400) while caller B is genuinely
        # blocked on the lock; B must make forward progress (re-load, retry its own
        # refresh) rather than deadlock. wait_for proves there's no hang.
        store = {
            "access_token": "OLD",
            "refresh_token": "RT",
            "access_expires_at": str(int(self.NOW) - 100),  # already expired
        }

        def fake_set(service, key, value):
            assert service == auth.SERVICE
            store[key] = value

        def fake_get(service, key):
            assert service == auth.SERVICE
            return store.get(key)

        # First POST fails, second succeeds. Both handlers await before responding
        # so the second caller is guaranteed to be blocked on the lock while the
        # first is mid-refresh — making the lock-release the thing under test.
        calls = {"n": 0}

        async def first_fails_then_succeeds(request):
            await asyncio.sleep(0)
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(
                200,
                json={
                    "access_token": "NEW",
                    "refresh_token": "RT2",
                    "expires_in": 1800,
                },
            )

        route = respx.post(auth.TOKEN_URL).mock(side_effect=first_fails_then_succeeds)

        # The module-level lock lazily binds to the first event loop that awaits it;
        # pytest-asyncio gives each test a fresh loop, so swap in a lock bound to THIS
        # loop (and assert against that same instance below). Order-independent.
        fresh_lock = asyncio.Lock()
        with (
            patch.object(auth, "_refresh_lock", fresh_lock),
            patch.object(auth.keyring, "set_password", side_effect=fake_set),
            patch.object(auth.keyring, "get_password", side_effect=fake_get),
            patch.object(auth.time, "time", return_value=self.NOW),
        ):
            results = await asyncio.wait_for(
                asyncio.gather(
                    auth.get_access_token("cid", "csec"),
                    auth.get_access_token("cid", "csec"),
                    return_exceptions=True,
                ),
                timeout=5,
            )
            # Same instance the code used — released both on failure and success.
            assert fresh_lock.locked() is False

        # Exactly one caller failed (scrubbed RuntimeError, no secret) and the other
        # made forward progress through its OWN refresh once the lock was released.
        errors = [r for r in results if isinstance(r, BaseException)]
        tokens = [r for r in results if not isinstance(r, BaseException)]
        assert len(errors) == 1
        assert isinstance(errors[0], RuntimeError)
        assert "HTTP 400" in str(errors[0])
        assert "RT" not in str(errors[0])  # the refresh token never leaks
        assert tokens == ["NEW"]
        # Two POSTs: A failed, then B retried under the released lock (the lock-was-
        # released assertion is checked above on the exact instance the code used).
        assert route.call_count == 2


class TestTransportHardening:
    @pytest.mark.parametrize(
        "invoke",
        [
            lambda: auth.exchange_code_for_tokens(
                "CODE", "cid", "csec", "https://127.0.0.1:8182"
            ),
            lambda: auth.refresh_access_token("RT", "cid", "csec"),
        ],
        ids=["exchange", "refresh"],
    )
    @respx.mock
    async def test_construction_contract(self, invoke):
        # Lock the security-relevant AsyncClient kwargs on the credential-bearing
        # token POSTs against future refactors — parity with client._get.
        real_cls = auth.httpx.AsyncClient
        captured: dict[str, object] = {}

        def spy(*args, **kwargs):
            captured.update(kwargs)
            return real_cls(*args, **kwargs)

        respx.post(auth.TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": "AT", "refresh_token": "RT", "expires_in": 1800},
            )
        )
        with patch.object(auth.httpx, "AsyncClient", side_effect=spy):
            await invoke()

        assert captured["trust_env"] is False
        assert captured["follow_redirects"] is False
        # finite timeout — isinstance alone would also pass httpx.Timeout(None).
        timeout = captured["timeout"]
        assert isinstance(timeout, httpx.Timeout)
        assert timeout.read == 10.0
        assert timeout.connect == 5.0
        # The positional 10.0 sets all four — pin write/pool too so a refactor to
        # Timeout(connect=5.0, read=10.0) can't silently leave them infinite.
        assert timeout.write == 10.0
        assert timeout.pool == 10.0
