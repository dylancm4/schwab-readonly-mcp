import httpx

from schwab_readonly_mcp.auth import Secret, scrubbed_http_error

BASE_URL = "https://api.schwabapi.com"

# Schwab's full transaction-type enum. The transactions endpoint is always
# sent an explicit `types` filter — when the caller doesn't narrow it, this
# all-values join means "no filter", mirroring the reference client (schwab-py
# never omits the parameter; the endpoint misbehaves without it).
ALL_TRANSACTION_TYPES = ",".join(
    (
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
)


def _safe_account_number(value: str) -> str:
    # read-only safety: account_number is interpolated into the URL path,
    # so reject anything that could traverse to another endpoint or inject a query.
    # Control chars (C0 incl. NUL, and DEL) are rejected here explicitly — NUL/DEL
    # are not isspace() and would otherwise slip past this denylist, leaving the
    # guarantee resting on downstream httpx behavior instead of the auditable check.
    # This denylist is sufficient only because the value lands in a path *segment*
    # behind the fixed BASE_URL host+scheme and httpx percent-encodes exotic path
    # bytes; revisit if the URL is ever built differently or the value moves to the host.
    if (
        not value
        or any(c.isspace() for c in value)
        or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value)
        or any(c in value for c in "/\\?#%")
        or ".." in value
        or value == "."
    ):
        raise ValueError("invalid account_number")
    return value


def _is_safe_path_segment(value: str) -> bool:
    # Predicate form of _safe_account_number's denylist, for values that are
    # not user-supplied account numbers (the bool return also avoids creating
    # an exception chain at the call site).
    try:
        _safe_account_number(value)
    except ValueError:
        return False
    return True


def _parse_account_hashes(payload: object) -> dict[str, str]:
    # Shape-check the accountNumbers payload (a list of
    # {"accountNumber": ..., "hashValue": ...} dicts) explicitly, so a
    # malformed or hostile body surfaces as one clear ValueError — never a
    # KeyError/TypeError that leaks payload structure. Defense in depth: the
    # hashValue lands in a URL path segment exactly like a user-supplied
    # account number, so even Schwab's own response must pass the same
    # denylist before it is ever cached.
    error = ValueError("malformed accountNumbers payload")
    if not isinstance(payload, list):
        raise error
    hashes: dict[str, str] = {}
    for entry in payload:
        if not isinstance(entry, dict):
            raise error
        number = entry.get("accountNumber")
        hash_value = entry.get("hashValue")
        if not isinstance(number, str) or not isinstance(hash_value, str):
            raise error
        if not _is_safe_path_segment(hash_value):
            raise error
        hashes[number] = hash_value
    return hashes


class SchwabClient:
    def __init__(self, access_token: str) -> None:
        self._access_token = Secret(access_token)
        # account number -> encrypted account hash, fetched lazily on the
        # first per-account call. Cached on this instance ONLY — never on
        # disk, never in a module global — because the mapping pairs real
        # account numbers with their hashes.
        self._account_hashes: dict[str, str] | None = None

    async def _get(
        self, path: str, params: dict[str, str | int] | None = None
    ) -> object:
        # int param values (e.g. period, frequency) are serialized to strings
        # on the wire by httpx, so callers may pass ints freely.
        async with httpx.AsyncClient(
            trust_env=False,
            timeout=httpx.Timeout(10.0, connect=5.0),
            # read-only — never auto-follow a redirect to another endpoint.
            follow_redirects=False,
        ) as client:
            try:
                response = await client.get(
                    f"{BASE_URL}{path}",
                    params=params,
                    headers={"Authorization": f"Bearer {self._access_token.reveal()}"},
                )
                response.raise_for_status()
            except httpx.HTTPError as e:
                # Build the scrubbed error here, but raise it OUTSIDE the except
                # block: with no active exception at the raise site, its
                # __context__ stays None, so the live secret-bearing httpx
                # request can't be reached by a crash reporter walking the chain.
                error = scrubbed_http_error(e)
            else:
                try:
                    payload = response.json()
                except ValueError:
                    # json.JSONDecodeError retains the FULL raw body on .doc,
                    # which here can carry account data. Replace it; the raise
                    # below (outside the except) keeps the chain severed.
                    error = ValueError("Schwab API returned non-JSON body")
                else:
                    return payload
        raise error

    async def _account_hash(self, account_number: str) -> str:
        # Schwab's per-account Trader endpoints reject the plaintext account
        # number (HTTP 400); they take the encrypted hash from the
        # accountNumbers endpoint — still a plain GET via _get, so the
        # read-only guarantee is untouched.
        if self._account_hashes is None:
            self._account_hashes = _parse_account_hashes(
                await self._get("/trader/v1/accounts/accountNumbers")
            )
        if account_number not in self._account_hashes:
            # Deliberately does NOT echo the user-supplied value (same
            # non-echoing contract as _safe_account_number).
            raise ValueError("account_number not found among accessible accounts")
        return self._account_hashes[account_number]

    async def list_accounts(self, include_positions: bool = True) -> object:
        params = {"fields": "positions"} if include_positions else None
        return await self._get("/trader/v1/accounts", params)

    async def get_account(
        self, account_number: str, include_positions: bool = True
    ) -> object:
        account_number = _safe_account_number(account_number)
        account_hash = await self._account_hash(account_number)
        params = {"fields": "positions"} if include_positions else None
        return await self._get(f"/trader/v1/accounts/{account_hash}", params)

    async def get_transactions(
        self,
        account_number: str,
        start_date: str,
        end_date: str,
        types: str = ALL_TRANSACTION_TYPES,
    ) -> object:
        account_number = _safe_account_number(account_number)
        account_hash = await self._account_hash(account_number)
        return await self._get(
            f"/trader/v1/accounts/{account_hash}/transactions",
            {"startDate": start_date, "endDate": end_date, "types": types},
        )

    async def get_quotes(self, symbols: list[str]) -> object:
        return await self._get(
            "/marketdata/v1/quotes",
            {"symbols": ",".join(symbols)},
        )

    async def get_price_history(
        self,
        symbol: str,
        period_type: str,
        period: int,
        frequency_type: str,
        frequency: int,
    ) -> object:
        return await self._get(
            "/marketdata/v1/pricehistory",
            {
                "symbol": symbol,
                "periodType": period_type,
                "period": period,
                "frequencyType": frequency_type,
                "frequency": frequency,
            },
        )
