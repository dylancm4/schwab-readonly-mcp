"""Shared security-assertion helpers.

pytest puts tests/ on sys.path (default import mode), so test modules import
these explicitly: ``from conftest import ...``. One copy each — the leak-walk
and the transport-hardening pin are the suite's most security-critical
assertions, and divergent per-module copies would silently under-assert.
"""

import httpx


def assert_chain_carries_no(exc: BaseException, *sentinels: str) -> None:
    # The teeth of the no-secret-leakage invariant: the top error's chain must
    # be severed (__context__/__cause__ both None), and every link reachable
    # anyway must not expose a sentinel via str/repr, a retained httpx
    # request's headers/body, or a json.JSONDecodeError's .doc (the FULL raw
    # body). Callers pass every secret-shaped sentinel, including the
    # base64-encoded Basic form of any credentials (a literal check alone is
    # base64-blind to an Authorization header).
    assert exc.__context__ is None
    assert exc.__cause__ is None
    seen: list[BaseException] = []
    cur: BaseException | None = exc
    while cur is not None and cur not in seen:
        seen.append(cur)
        text = repr(cur) + str(cur) + str(getattr(cur, "doc", ""))
        req = getattr(cur, "request", None)
        if req is not None:
            text += repr(dict(req.headers)) + req.content.decode("utf-8", "replace")
        for leaked in sentinels:
            assert leaked not in text
        cur = cur.__context__ or cur.__cause__


def assert_hardened_client_kwargs(captured: dict[str, object]) -> None:
    # Lock the security-relevant httpx.AsyncClient kwargs against refactors —
    # one copy shared by both construction sites (auth token POST, client GET).
    assert captured["trust_env"] is False
    assert captured["follow_redirects"] is False
    # TLS verification must never be disabled — absent kwarg means the httpx
    # default (True); anything else (False, custom context) must fail loudly.
    assert captured.get("verify", True) is True
    # finite timeout — isinstance alone would also pass httpx.Timeout(None).
    timeout = captured["timeout"]
    assert isinstance(timeout, httpx.Timeout)
    assert timeout.read == 10.0
    assert timeout.connect == 5.0
    # The positional 10.0 sets all four — pin write/pool too so a refactor to
    # Timeout(connect=5.0, read=10.0) can't silently leave them infinite.
    assert timeout.write == 10.0
    assert timeout.pool == 10.0
