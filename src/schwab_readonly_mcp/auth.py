import asyncio
import time
from dataclasses import dataclass

import httpx
import keyring

SERVICE = "schwab-readonly-mcp"
TOKEN_URL = "https://api.schwabapi.com/v1/oauth/token"
# Refresh when an access token is within this many seconds of expiry. Used at
# both the pre-lock check and the in-lock re-check in get_access_token; they
# MUST share one value or the double-checked-lock re-check semantics drift.
REFRESH_SKEW_SECONDS = 30

# Serializes the near-expiry refresh path in get_access_token. FastMCP serves
# tool calls concurrently and Schwab rotates the refresh token on use, so two
# concurrent refreshes would invalidate each other's new refresh token.
_refresh_lock = asyncio.Lock()


class Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str | Secret) -> None:
        # Unwrap a stray double-wrap so reveal() always returns the raw value,
        # never a nested Secret.
        if isinstance(value, Secret):
            value = value.reveal()
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('<redacted>')"

    def __str__(self) -> str:
        return "<redacted>"

    def __format__(self, format_spec: str) -> str:
        return "<redacted>"

    def __reduce__(self) -> tuple:
        return (Secret, ("<redacted>",))

    def __getstate__(self) -> object:
        # __reduce__ governs pickle/copy (both redact), but a direct
        # __getstate__() call on a __slots__ object would otherwise return the
        # raw value. Redact this introspection path too.
        return (None, {"_value": "<redacted>"})

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Secret):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._value)


@dataclass(frozen=True)
class TokenSet:
    access_token: Secret
    refresh_token: Secret
    access_expires_at: int


def store_tokens(tokens: TokenSet) -> None:
    # Write access_expires_at LAST. These three Keychain entries are written
    # non-atomically; if the process dies mid-write, a missing/stale expiry makes
    # the next load_tokens either raise "No tokens stored" (loud, safe → re-authorize)
    # or look already-expired (→ triggers a refresh), rather than handing out a
    # fresh access token paired with a stale expiry.
    keyring.set_password(SERVICE, "access_token", tokens.access_token.reveal())
    keyring.set_password(SERVICE, "refresh_token", tokens.refresh_token.reveal())
    keyring.set_password(SERVICE, "access_expires_at", str(tokens.access_expires_at))


def load_tokens() -> TokenSet:
    access = keyring.get_password(SERVICE, "access_token")
    refresh = keyring.get_password(SERVICE, "refresh_token")
    expires = keyring.get_password(SERVICE, "access_expires_at")
    if access is None or refresh is None or expires is None:
        raise RuntimeError("No tokens stored: run scripts/authorize.py first")
    if not access or not refresh:
        # store_tokens can never write "" (_require_str rejects it), so an empty
        # entry is hand-edited/corrupted Keychain state — fail loud here, not as
        # an opaque Schwab 401 later.
        raise RuntimeError("corrupt tokens: re-run scripts/authorize.py")
    try:
        expires_at = int(expires)
    except ValueError:
        raise RuntimeError("corrupt tokens: re-run scripts/authorize.py") from None
    return TokenSet(
        access_token=Secret(access),
        refresh_token=Secret(refresh),
        access_expires_at=expires_at,
    )


def scrubbed_http_error(exc: httpx.HTTPError) -> RuntimeError:
    # The httpx exception retains the live request, whose headers carry
    # credentials and whose body can carry secrets (the OAuth code /
    # refresh token). Surface only a safe summary so the secret-bearing
    # request is never propagated to logs or a crash reporter. Callers must
    # raise the result OUTSIDE the except block so no active exception sets
    # __context__ back to the original (secret-bearing) httpx error.
    # Reading exc.response.status_code (an int) and
    # type(exc).__name__ is safe; never embed str(exc), the request, or the
    # response object in the message.
    if isinstance(exc, httpx.HTTPStatusError):
        return RuntimeError(f"Schwab API returned HTTP {exc.response.status_code}")
    return RuntimeError(f"Schwab API request failed: {type(exc).__name__}")


def _require_str(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"token endpoint returned invalid {key}")
    return value


def _require_int(payload: dict[str, object], key: str) -> int:
    value = payload.get(key)
    # bool is a subclass of int — reject explicitly so `{"expires_in": true}`
    # doesn't silently become an immediate-refresh expiry.
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"token endpoint returned invalid {key}")
    return value


async def _post_token_request(
    data: dict[str, str], client_id: str, client_secret: str
) -> dict[str, object]:
    # The single hardened POST both token-endpoint functions share, so the
    # scrub logic has exactly one copy a future fix can land in.
    async with httpx.AsyncClient(
        trust_env=False,
        timeout=httpx.Timeout(10.0, connect=5.0),
        # read-only: never auto-follow a redirect off the fixed token endpoint
        # (parity with client.py; makes the invariant explicit, not default-dependent).
        follow_redirects=False,
    ) as client:
        try:
            response = await client.post(
                TOKEN_URL, auth=(client_id, client_secret), data=data
            )
            response.raise_for_status()
        except httpx.HTTPError as e:
            # Build the scrubbed error here, but raise it OUTSIDE the except
            # block (after the `with`): with no active exception at the raise
            # site its __context__ stays None, so the live request carrying the
            # Basic creds + grant secret (OAuth code / refresh token) can't be
            # reached via the exception chain.
            error = scrubbed_http_error(e)
        else:
            try:
                payload = response.json()
            except ValueError:
                # json.JSONDecodeError retains the FULL raw body on .doc, which
                # on this endpoint can carry token material. Replace it; the
                # raise below (outside the except) keeps the chain severed.
                error = ValueError("token endpoint returned non-JSON body")
            else:
                if isinstance(payload, dict):
                    return payload
                # Valid JSON but not an object (e.g. [] or "x"): keep the
                # module's loud ValueError contract instead of an
                # AttributeError from payload.get downstream.
                error = ValueError("token endpoint returned non-JSON-object body")
    raise error


async def exchange_code_for_tokens(
    code: str, client_id: str, client_secret: str, redirect_uri: str
) -> TokenSet:
    payload = await _post_token_request(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        },
        client_id,
        client_secret,
    )
    return TokenSet(
        access_token=Secret(_require_str(payload, "access_token")),
        refresh_token=Secret(_require_str(payload, "refresh_token")),
        access_expires_at=int(time.time()) + _require_int(payload, "expires_in"),
    )


async def refresh_access_token(
    refresh_token: str, client_id: str, client_secret: str
) -> TokenSet:
    payload = await _post_token_request(
        {"grant_type": "refresh_token", "refresh_token": refresh_token},
        client_id,
        client_secret,
    )
    new_rt = payload.get("refresh_token") or refresh_token
    if not isinstance(new_rt, str) or not new_rt:
        raise ValueError("token endpoint returned invalid refresh_token")
    return TokenSet(
        access_token=Secret(_require_str(payload, "access_token")),
        refresh_token=Secret(new_rt),
        access_expires_at=int(time.time()) + _require_int(payload, "expires_in"),
    )


async def get_access_token(client_id: str, client_secret: str) -> str:
    loaded = load_tokens()
    if loaded.access_expires_at - time.time() >= REFRESH_SKEW_SECONDS:
        return loaded.access_token.reveal()
    # Near expiry. Serialize refresh — Schwab rotates the refresh token on use,
    # so two concurrent refreshes would invalidate each other. Re-load + re-check
    # inside the lock: another coroutine may have refreshed while we waited.
    async with _refresh_lock:
        loaded = load_tokens()
        if loaded.access_expires_at - time.time() >= REFRESH_SKEW_SECONDS:
            return loaded.access_token.reveal()
        new = await refresh_access_token(
            loaded.refresh_token.reveal(), client_id, client_secret
        )
        store_tokens(new)
        return new.access_token.reveal()
