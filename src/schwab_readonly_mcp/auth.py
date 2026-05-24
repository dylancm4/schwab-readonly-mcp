import time
from dataclasses import dataclass

import httpx
import keyring

SERVICE = "schwab-readonly-mcp"
TOKEN_URL = "https://api.schwabapi.com/v1/oauth/token"


class Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        object.__setattr__(self, "_value", value)

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
    keyring.set_password(SERVICE, "access_token", tokens.access_token.reveal())
    keyring.set_password(SERVICE, "refresh_token", tokens.refresh_token.reveal())
    keyring.set_password(SERVICE, "access_expires_at", str(tokens.access_expires_at))


def load_tokens() -> TokenSet:
    access = keyring.get_password(SERVICE, "access_token")
    refresh = keyring.get_password(SERVICE, "refresh_token")
    expires = keyring.get_password(SERVICE, "access_expires_at")
    if access is None or refresh is None or expires is None:
        raise RuntimeError("No tokens stored: run scripts/authorize.py first")
    return TokenSet(
        access_token=Secret(access),
        refresh_token=Secret(refresh),
        access_expires_at=int(expires),
    )


async def exchange_code_for_tokens(
    code: str, client_id: str, client_secret: str, redirect_uri: str
) -> TokenSet:
    async with httpx.AsyncClient(trust_env=False) as client:
        response = await client.post(
            TOKEN_URL,
            auth=(client_id, client_secret),
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
        response.raise_for_status()
        payload = response.json()
    return TokenSet(
        access_token=Secret(payload["access_token"]),
        refresh_token=Secret(payload["refresh_token"]),
        access_expires_at=int(time.time()) + payload["expires_in"],
    )


async def refresh_access_token(
    refresh_token: str, client_id: str, client_secret: str
) -> TokenSet:
    async with httpx.AsyncClient(trust_env=False) as client:
        response = await client.post(
            TOKEN_URL,
            auth=(client_id, client_secret),
            data={"grant_type": "refresh_token", "refresh_token": refresh_token},
        )
        response.raise_for_status()
        payload = response.json()
    new_rt = payload.get("refresh_token") or refresh_token
    return TokenSet(
        access_token=Secret(payload["access_token"]),
        refresh_token=Secret(new_rt),
        access_expires_at=int(time.time()) + payload["expires_in"],
    )


async def get_access_token(client_id: str, client_secret: str) -> str:
    loaded = load_tokens()
    if loaded.access_expires_at - time.time() < 30:
        new = await refresh_access_token(
            loaded.refresh_token.reveal(), client_id, client_secret
        )
        store_tokens(new)
        return new.access_token.reveal()
    return loaded.access_token.reveal()
