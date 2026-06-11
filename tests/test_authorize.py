import errno
import http.server
import importlib.util
import os
import pathlib
import shlex
import shutil
import socket
import ssl
import subprocess
import threading
import time
import webbrowser
from unittest.mock import patch
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
        # REDIRECT_URI is deliberately NOT derived from HOST/PORT (byte-match to
        # the registered callback) — so pin that the three constants agree, or a
        # PORT edit would leave the server listening where Schwab never redirects.
        assert urlsplit(authorize.REDIRECT_URI).netloc == (
            f"{authorize.HOST}:{authorize.PORT}"
        )
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
        # !r form: the value is repr-quoted so control bytes can't reach the
        # terminal raw (see the escape-injection test below).
        with pytest.raises(RuntimeError, match="OAuth error: 'access_denied'"):
            authorize.parse_callback("/?error=access_denied&state=STATE", "STATE")

    def test_error_param_control_chars_not_echoed_raw(self):
        # Defense-in-depth: the error param is attacker-influenced text that
        # escapes to the operator's terminal; ANSI/control bytes (ESC, BEL)
        # must surface repr-escaped, never raw terminal-escape injection.
        with pytest.raises(RuntimeError) as excinfo:
            authorize.parse_callback("/?error=%1B%5D0%3Bpwned%07&state=STATE", "STATE")
        message = str(excinfo.value)
        assert "\x1b" not in message
        assert "\x07" not in message
        assert "\\x1b" in message  # repr-escaped, still diagnosable

    def test_raises_on_missing_code(self):
        with pytest.raises(RuntimeError, match="missing authorization code"):
            authorize.parse_callback("/?state=STATE", "STATE")

    def test_raises_on_blank_code(self):
        with pytest.raises(RuntimeError, match="missing authorization code"):
            authorize.parse_callback("/?code=&state=STATE", "STATE")

    def test_raises_runtime_error_on_non_ascii_state(self):
        # returned_state is attacker-controllable; compare_digest(str, str)
        # raises TypeError on non-ASCII input. The contract is the documented
        # RuntimeError, not a TypeError from the comparison primitive.
        with pytest.raises(RuntimeError, match="state mismatch"):
            authorize.parse_callback("/?code=A&state=%C3%A9", "STATE")


class TestSmokeTestCommand:
    def test_readme_contains_the_exact_one_liner_exactly_once(self):
        # README step 4 claims "The helper prints this exact one-liner on
        # success" — pin the byte-for-byte duplication so they cannot drift.
        readme = (
            pathlib.Path(__file__).resolve().parent.parent / "README.md"
        ).read_text()
        assert readme.count(authorize._smoke_test_command()) == 1

    def test_one_liner_shell_splits_and_payload_compiles(self):
        # The truncation/quoting logic lives inline in the -c payload, so no
        # other test executes it. Pin that the quoting survives a shell split
        # and that the payload is valid Python carrying the truncation logic —
        # README byte-sync alone would let both copies be in-sync-and-broken.
        parts = shlex.split(authorize._smoke_test_command())
        assert parts[:4] == ["uv", "run", "python", "-c"]
        payload = parts[4]
        compile(payload, "<smoke>", "exec")
        assert str(authorize.SMOKE_TEST_MAX_CHARS) in payload
        assert "truncated" in payload


class TestRequireCredentials:
    # Mirror tests/test_server.py TestCredentials: missing/empty config is a
    # clean operator error that names only the ABSENCE — a partially-set env is
    # exactly where a real secret value exists to leak into the message.

    @pytest.mark.parametrize(
        "env",
        [
            {},
            {"SCHWAB_CLIENT_ID": "the-id-value"},
            {"SCHWAB_CLIENT_SECRET": "the-secret-value"},
            {"SCHWAB_CLIENT_ID": "the-id-value", "SCHWAB_CLIENT_SECRET": ""},
            {"SCHWAB_CLIENT_ID": "", "SCHWAB_CLIENT_SECRET": "the-secret-value"},
            {"SCHWAB_CLIENT_ID": "", "SCHWAB_CLIENT_SECRET": ""},
        ],
    )
    def test_missing_or_empty_exits_without_echoing_values(self, env):
        with patch.dict(os.environ, env, clear=True):
            with pytest.raises(SystemExit) as excinfo:
                authorize._require_credentials()
        # The error must name the variables, never echo a configured value.
        message = str(excinfo.value)
        assert "SCHWAB_CLIENT_ID" in message
        assert "SCHWAB_CLIENT_SECRET" in message
        assert "the-id-value" not in message
        assert "the-secret-value" not in message

    def test_happy_path_returns_tuple(self):
        env = {"SCHWAB_CLIENT_ID": "cid", "SCHWAB_CLIENT_SECRET": "csec"}
        with patch.dict(os.environ, env, clear=True):
            assert authorize._require_credentials() == ("cid", "csec")


class TestRequireCert:
    def test_missing_cert_or_key_exits_with_openssl_hint(self, monkeypatch):
        # An absent cert/key is an operator-config error: a clean SystemExit
        # carrying the exact openssl command — never a raw ssl/FileNotFoundError.
        monkeypatch.setattr(os.path, "exists", lambda _path: False)
        with pytest.raises(SystemExit) as excinfo:
            authorize._require_cert()
        message = str(excinfo.value)
        assert "openssl req" in message
        assert authorize.CERT_FILE in message
        assert authorize.KEY_FILE in message


class TestCaptureCallback:
    def test_port_already_in_use_exits_with_actionable_message(self, monkeypatch):
        # A wedged prior run / another local service on 8182 is an operator-
        # environment error: SystemExit with a clear message, never a raw
        # OSError(EADDRINUSE) traceback. Nothing secret exists at this point.
        def busy_init(self, *args: object, **kwargs: object) -> None:
            raise OSError(errno.EADDRINUSE, "Address already in use")

        monkeypatch.setattr(http.server.HTTPServer, "__init__", busy_init)
        with pytest.raises(SystemExit) as excinfo:
            authorize._capture_callback(object())
        message = str(excinfo.value)
        assert f"{authorize.HOST}:{authorize.PORT}" in message
        assert "already in use" in message

    def test_survives_aborted_tls_handshake_then_returns_real_callback(
        self, tmp_path, monkeypatch, capfd
    ):
        # The documented happy path guarantees a non-callback connection: the
        # browser's self-signed-cert interstitial aborts its TLS handshake
        # (speculative preconnects do the same). That abort must not consume
        # the flow's only accept and lose the real callback that follows.
        openssl = shutil.which("openssl")
        if openssl is None:
            pytest.skip("openssl binary not available")
        cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
        subprocess.run(
            [
                openssl,
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-nodes",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert), keyfile=str(key))

        # Ephemeral port so the test never collides with a real run on 8182.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        monkeypatch.setattr(authorize, "PORT", port)

        # Loopback-only binding is a locked security decision; spy on the
        # address _capture_callback actually passes to HTTPServer so a widened
        # bind (e.g. "0.0.0.0") fails here instead of landing silently.
        binds: list[object] = []
        real_init = http.server.HTTPServer.__init__

        def spy_init(self, server_address, *args: object, **kwargs: object) -> None:
            binds.append(server_address)
            real_init(self, server_address, *args, **kwargs)

        monkeypatch.setattr(http.server.HTTPServer, "__init__", spy_init)

        result: dict[str, object] = {}

        def run() -> None:
            try:
                result["path"] = authorize._capture_callback(context)
            except Exception as exc:  # surface the failure in the assert below
                result["error"] = exc

        # daemon=True: if the server thread wedges in accept(), a failing test
        # must stay a failing test — a non-daemon thread would hang pytest at
        # interpreter exit. The is_alive() assert below still catches the wedge.
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        try:
            # 1) A verifying client rejects the self-signed cert and aborts the
            # handshake — the server sees an SSLError inside get_request().
            # (Retry the connect until the thread's server is listening.)
            deadline = time.monotonic() + 5
            while True:
                try:
                    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
                    break
                except ConnectionRefusedError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.01)
            verifying = ssl.create_default_context()
            with raw:
                with pytest.raises(ssl.SSLError):
                    verifying.wrap_socket(raw, server_hostname="127.0.0.1")
            # 2) The real callback, from a client that trusts this exact cert.
            trusting = ssl.create_default_context(cafile=str(cert))
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with trusting.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                    tls.sendall(
                        b"GET /?code=ABC&state=S HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
                    )
                    response = tls.recv(4096)
            assert b" 200 " in response.split(b"\r\n", 1)[0]
        finally:
            thread.join(timeout=10)
        assert not thread.is_alive()
        assert result.get("error") is None
        assert result.get("path") == "/?code=ABC&state=S"
        # Exactly one server, bound to loopback — never a wildcard interface.
        assert binds == [("127.0.0.1", port)]
        # The handler must never log the request line — it carries the
        # authorization code. capfd captures at the fd level, so it sees the
        # handler thread's stderr; this fails if log_message silencing regresses.
        out, err = capfd.readouterr()
        assert "ABC" not in out + err
        assert "code=" not in out + err


class TestMainPrintSurface:
    def test_main_never_prints_secret_code_or_token_values(self, monkeypatch, capsys):
        # main() is the only orchestration path that prints; pin its output
        # surface so a future edit echoing the client secret, the authorization
        # code, or a token value fails here. The client_id and state inside the
        # printed authorize URL are expected and allowed.
        fixed_state = "FIXED-STATE-SENTINEL"
        monkeypatch.setenv("SCHWAB_CLIENT_ID", "CID-SENTINEL")
        monkeypatch.setenv("SCHWAB_CLIENT_SECRET", "CSEC-SENTINEL")
        monkeypatch.setattr(
            authorize.secrets, "token_urlsafe", lambda *_a, **_k: fixed_state
        )
        monkeypatch.setattr(authorize, "_require_cert", lambda: object())
        monkeypatch.setattr(authorize.webbrowser, "open", lambda *_a, **_k: True)
        # Canned callback through the REAL parse_callback (fixed state matches).
        monkeypatch.setattr(
            authorize,
            "_capture_callback",
            lambda _context: f"/?code=CANNEDCODE&state={fixed_state}",
        )
        tokens = authorize.auth.TokenSet(
            access_token=authorize.auth.Secret("ACCESS-SENTINEL"),
            refresh_token=authorize.auth.Secret("REFRESH-SENTINEL"),
            access_expires_at=2_000_000_000,
        )

        async def fake_exchange(code, client_id, client_secret, redirect_uri):
            assert code == "CANNEDCODE"
            return tokens

        stored: list[object] = []
        monkeypatch.setattr(authorize.auth, "exchange_code_for_tokens", fake_exchange)
        monkeypatch.setattr(authorize.auth, "store_tokens", stored.append)

        authorize.main()

        assert stored == [tokens]  # the flow genuinely completed
        out, err = capsys.readouterr()
        output = out + err
        # Expected, allowed output: the authorize URL (carries id + state).
        assert "CID-SENTINEL" in output
        assert fixed_state in output
        # Never the secret, the authorization code, or a token value.
        assert "CSEC-SENTINEL" not in output
        assert "CANNEDCODE" not in output
        assert "ACCESS-SENTINEL" not in output
        assert "REFRESH-SENTINEL" not in output


class TestModuleImportIsSideEffectFree:
    def test_importing_does_not_open_browser_or_serve(self, monkeypatch):
        # Re-execute the script from its path under spies: a stray module-level
        # webbrowser.open() would otherwise open a browser on every test run
        # while a callable-only check still passed, and a module-level
        # HTTPServer(...) would bind a socket. Both must be impossible.
        opened: list[object] = []
        monkeypatch.setattr(webbrowser, "open", lambda *a, **k: opened.append(a))

        def _no_serve(*args: object, **kwargs: object) -> None:
            raise AssertionError("HTTPServer constructed at import time")

        monkeypatch.setattr(http.server.HTTPServer, "__init__", _no_serve)
        spec = importlib.util.spec_from_file_location(
            "authorize_reimport", _AUTHORIZE_PATH
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert opened == []
        assert callable(module.main)
        assert callable(module.build_authorize_url)
        assert callable(module.parse_callback)
