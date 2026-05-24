import time
from dataclasses import dataclass

import httpx
import keyring

SERVICE = "schwab-readonly-mcp"
TOKEN_URL = "https://api.schwabapi.com/v1/oauth/token"


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    refresh_token: str
    access_expires_at: int

    def __repr__(self) -> str:
        return (
            f"TokenSet(access_token=<redacted>, refresh_token=<redacted>, "
            f"access_expires_at={self.access_expires_at})"
        )


def store_tokens(tokens: TokenSet) -> None:
    keyring.set_password(SERVICE, "access_token", tokens.access_token)
    keyring.set_password(SERVICE, "refresh_token", tokens.refresh_token)
    keyring.set_password(SERVICE, "access_expires_at", str(tokens.access_expires_at))


def load_tokens() -> TokenSet:
    access = keyring.get_password(SERVICE, "access_token")
    refresh = keyring.get_password(SERVICE, "refresh_token")
    expires = keyring.get_password(SERVICE, "access_expires_at")
    if access is None or refresh is None or expires is None:
        raise RuntimeError("No tokens stored: run scripts/authorize.py first")
    return TokenSet(
        access_token=access,
        refresh_token=refresh,
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
        access_token=payload["access_token"],
        refresh_token=payload["refresh_token"],
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
    return TokenSet(
        access_token=payload["access_token"],
        refresh_token=payload.get("refresh_token") or refresh_token,
        access_expires_at=int(time.time()) + payload["expires_in"],
    )


async def get_access_token(client_id: str, client_secret: str) -> str:
    loaded = load_tokens()
    if loaded.access_expires_at - time.time() < 30:
        new = await refresh_access_token(loaded.refresh_token, client_id, client_secret)
        store_tokens(new)
        return new.access_token
    return loaded.access_token
