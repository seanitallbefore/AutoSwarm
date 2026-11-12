import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

from autoswarm import engine, platform
from autoswarm.providers import invocation
from autoswarm.records import Records, SwarmError, read_json, write_json

if __package__:
    from .autoswarm_test_support import cleanup_temporary
else:
    from autoswarm_test_support import cleanup_temporary


FIXTURE = Path(__file__).parent / "fixtures/provider.py"


class ACPAuthenticateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.records = Records(self.root / "state")
        self.trace = self.root / "trace.jsonl"
        self.ids = []

    def tearDown(self):
        for call_id in self.ids:
            engine.cancel(self.records, call_id)
        deadline = time.monotonic() + 10  # Test harness deadline, not product policy.
        while any(platform.running(read_json(self.records.call(value) / "handle.json")) for value in self.ids) and time.monotonic() < deadline:
            time.sleep(0.01)
        cleanup_temporary(self.temporary, deadline)

    def run_fixture(self, *flags, provider="antigravity", **settings):
        self.trace.unlink(missing_ok=True)
        command = [sys.executable, str(FIXTURE), provider, "--selection-trace=" + str(self.trace), *flags]
        write_json(self.records.home / "config.json", {"providers": {provider: {"command": command, **settings}}})
        call_id = engine.start_call(self.records, provider, "hello", self.root)["call_id"]
        self.ids.append(call_id)
        result = engine.wait(self.records, [call_id])[0]
        methods = [json.loads(line).get("method") for line in self.trace.read_text(encoding="utf-8").splitlines()]
        return result, methods

    def test_authenticates_with_configured_method_then_retries_session_once(self):
        for provider in ("antigravity", "gemini"):
            with self.subTest(provider=provider):
                result, methods = self.run_fixture("auth-required", "auth-methods", provider=provider, auth_method="oauth-personal")
                self.assertEqual(result["outcome"], "completed", result)
                self.assertEqual(result["content"], "hello|session=fixture-session")
                self.assertEqual([item for item in methods if item in {"session/new", "authenticate"}], ["session/new", "authenticate", "session/new"])

    def test_resumed_session_load_also_authenticates_once(self):
        first, _ = self.run_fixture("auth-required", "auth-methods", auth_method="oauth-personal")
        self.trace.unlink()
        continued = engine.resume(self.records, first["call_id"], "follow up")
        self.ids.append(continued["call_id"])
        result = engine.wait(self.records, [continued["call_id"]])[0]
        self.assertEqual(result["outcome"], "completed", result)
        methods = [json.loads(line).get("method") for line in self.trace.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([item for item in methods if item in {"session/load", "authenticate"}], ["session/load", "authenticate", "session/load"])

    def test_no_configured_method_names_advertised_methods_and_config_key(self):
        result, methods = self.run_fixture("auth-required", "auth-methods")
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["error_code"], "native_auth_required")
        for text in ("oauth-personal", "api-key", "providers.antigravity.auth_method"):
            self.assertIn(text, result["error"])
        self.assertNotIn("authenticate", methods)

    def test_unadvertised_method_is_not_sent(self):
        result, methods = self.run_fixture("auth-required", "auth-methods", auth_method="device-code")
        self.assertEqual(result["error_code"], "native_auth_required")
        self.assertIn("device-code", result["error"])
        self.assertNotIn("authenticate", methods)

    def test_authenticate_error_is_reported(self):
        result, methods = self.run_fixture("auth-required", "auth-methods", "auth-reject", auth_method="oauth-personal")
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["error_code"], "native_auth_failed")
        self.assertIn("Fixture sign-in was cancelled", result["error"])
        self.assertEqual(methods.count("session/new"), 1)

    def test_authenticate_timeout_is_reported(self):
        result, methods = self.run_fixture("auth-required", "auth-methods", "auth-hold", auth_method="oauth-personal", auth_timeout=0.5)
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["error_code"], "native_auth_timeout")
        self.assertIn("providers.antigravity.auth_timeout", result["error"])
        self.assertEqual(methods.count("authenticate"), 1)

    def test_session_still_refused_after_authenticate_does_not_loop(self):
        result, methods = self.run_fixture("auth-required", "auth-methods", "auth-ineffective", auth_method="oauth-personal")
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["error_code"], "native_auth_required")
        self.assertEqual([item for item in methods if item in {"session/new", "authenticate"}], ["session/new", "authenticate", "session/new"])

    def test_configured_method_is_unused_when_session_opens(self):
        result, methods = self.run_fixture("auth-methods", auth_method="oauth-personal")
        self.assertEqual(result["outcome"], "completed", result)
        self.assertNotIn("authenticate", methods)

    def test_auth_settings_are_validated(self):
        command = [sys.executable, str(FIXTURE), "antigravity"]
        for settings in ({"auth_method": ""}, {"auth_method": 1}, {"auth_method": "oauth-personal", "auth_timeout": 0}, {"auth_method": "oauth-personal", "auth_timeout": True}):
            with self.subTest(settings=settings), self.assertRaises(SwarmError) as caught:
                invocation({"provider": "antigravity"}, {"providers": {"antigravity": {"command": command, **settings}}})
            self.assertEqual(caught.exception.code, "invalid_config")
        task = {"provider": "antigravity"}
        invocation(task, {"providers": {"antigravity": {"command": command}}})
        self.assertNotIn("native_auth", task)


if __name__ == "__main__":
    unittest.main()
