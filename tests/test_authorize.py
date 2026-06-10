import importlib.util
import pathlib
from urllib.parse import parse_qs, urlsplit

import pytest

# scripts/ is not part of the installed package, so import authorize.py straight
# from its file path via an importlib spec — no sys.path mutation, no install.
_AUTHORIZE_PATH = (
    pathlib.Path(__file__).resolve().parent.parent / "scripts" / "authorize.py"
)
_spec = importlib.util.spec_from_file_location("authorize", _AUTHORIZE_PATH)
authorize = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(authorize)


class TestBuildAuthorizeUrl:
    def test_builds_expected_query(self):
        url = authorize.build_authorize_url("CID", "https://127.0.0.1:8182", "STATE")
        parts = urlsplit(url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == authorize.AUTHORIZE_URL
        params = parse_qs(parts.query)
        assert params["response_type"] == ["code"]
        assert params["client_id"] == ["CID"]
        assert params["redirect_uri"] == ["https://127.0.0.1:8182"]
        assert params["state"] == ["STATE"]

    def test_redirect_uri_byte_matches_registered_callback(self):
        # The registered Schwab callback is compared by exact string — no trailing
        # slash. Pin that the module constant the flow actually uses matches.
        assert authorize.REDIRECT_URI == "https://127.0.0.1:8182"
        url = authorize.build_authorize_url("CID", authorize.REDIRECT_URI, "STATE")
        params = parse_qs(urlsplit(url).query)
        assert params["redirect_uri"] == ["https://127.0.0.1:8182"]

    def test_special_characters_are_percent_encoded(self):
        # A client_id with reserved chars must be encoded, not break the query.
        url = authorize.build_authorize_url("a b&c=d", "https://127.0.0.1:8182", "s/t")
        params = parse_qs(urlsplit(url).query)
        assert params["client_id"] == ["a b&c=d"]
        assert params["state"] == ["s/t"]


class TestParseCallback:
    def test_returns_code_on_valid_callback(self):
        code = authorize.parse_callback("/?code=ABC123&state=STATE", "STATE")
        assert code == "ABC123"

    def test_ignores_extra_params(self):
        code = authorize.parse_callback("/?code=ABC&state=STATE&session=xyz", "STATE")
        assert code == "ABC"

    def test_raises_on_state_mismatch(self):
        with pytest.raises(RuntimeError, match="state mismatch"):
            authorize.parse_callback("/?code=ABC&state=WRONG", "STATE")

    def test_raises_on_missing_state(self):
        with pytest.raises(RuntimeError, match="state mismatch"):
            authorize.parse_callback("/?code=ABC", "STATE")

    def test_empty_expected_state_is_never_satisfiable(self):
        # A degenerate empty expected_state must not be matchable by an empty
        # returned state — otherwise CSRF protection silently disappears.
        with pytest.raises(RuntimeError, match="state mismatch"):
            authorize.parse_callback("/?code=ABC&state=", "")

    def test_state_checked_before_error_param(self):
        # A forged callback carrying both a wrong state and an error must be
        # rejected for the state mismatch first — never trust its error text.
        with pytest.raises(RuntimeError, match="state mismatch"):
            authorize.parse_callback("/?error=denied&state=WRONG", "STATE")

    def test_raises_on_schwab_error_param(self):
        with pytest.raises(RuntimeError, match="OAuth error: access_denied"):
            authorize.parse_callback("/?error=access_denied&state=STATE", "STATE")

    def test_raises_on_missing_code(self):
        with pytest.raises(RuntimeError, match="missing authorization code"):
            authorize.parse_callback("/?state=STATE", "STATE")

    def test_raises_on_blank_code(self):
        with pytest.raises(RuntimeError, match="missing authorization code"):
            authorize.parse_callback("/?code=&state=STATE", "STATE")


class TestTruncateForDisplay:
    def test_returns_short_text_unchanged(self):
        assert authorize.truncate_for_display("hello", 100) == "hello"

    def test_returns_text_at_exact_limit_unchanged(self):
        text = "x" * 50
        assert authorize.truncate_for_display(text, 50) == text

    def test_truncates_long_text_with_marker(self):
        text = "x" * 100
        out = authorize.truncate_for_display(text, 10)
        assert out.startswith("x" * 10)
        assert "truncated" in out
        assert "100 chars total" in out

    def test_default_limit_is_applied(self):
        text = "y" * (authorize.SMOKE_TEST_MAX_CHARS + 1)
        out = authorize.truncate_for_display(text)
        assert out.startswith("y" * authorize.SMOKE_TEST_MAX_CHARS)
        assert "truncated" in out


class TestModuleImportIsSideEffectFree:
    def test_importing_does_not_open_browser_or_serve(self):
        # Re-importing the script from its path must not trigger the interactive
        # flow (no browser, no socket bind). If main() ran on import, this module
        # load (already done at top of file) would have hung or raised — reaching
        # here at all is the assertion; we also confirm the entrypoints exist.
        assert callable(authorize.main)
        assert callable(authorize.build_authorize_url)
        assert callable(authorize.parse_callback)
        assert callable(authorize.truncate_for_display)
