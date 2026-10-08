"""Controller-side GitHub registration tests; every HTTP boundary is mocked."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock
import urllib.error
import urllib.request


SCRIPT = Path(__file__).resolve().parents[2] / "ops" / "github_registration.py"
PAT = "ghp_" + "a" * 36
TOKEN = "ABC123" * 5
NOW = datetime(2026, 10, 2, 12, 0, tzinfo=timezone.utc)
EXPIRY = "2026-10-02T13:00:00Z"


class Response:
    def __init__(self, body=None, status=201):
        self.body = body if body is not None else json.dumps(
            {"token": TOKEN, "expires_at": EXPIRY}
        ).encode()
        self.status = status
        self.headers = {"Date": "Fri, 02 Oct 2026 12:00:00 GMT"}
        self.read_limits = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit):
        self.read_limits.append(limit)
        return self.body[:limit]


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.pat_file = self.root / "pat"
        self.pat_file.write_text(PAT)
        self.pat_file.chmod(0o600)
        self.output = self.root / "registration"
        self.module = None

    def load(self):
        if self.module is None:
            spec = importlib.util.spec_from_file_location("github_registration", SCRIPT)
            self.module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.module)
        return self.module

    def invoke(self, response=None, error=None, repository=None):
        module = self.load()
        opener = mock.Mock()
        if error is None:
            opener.open.return_value = response or Response()
        else:
            opener.open.side_effect = error
        args = ["--pat-file", str(self.pat_file), "--output", str(self.output)]
        if repository is not None:
            args.extend(["--repository", repository])
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(module.urllib.request, "build_opener", return_value=opener) as builder:
            with mock.patch.object(module, "utc_now", return_value=NOW):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = module.main(args)
        return result, stdout.getvalue(), stderr.getvalue(), opener, builder

    def assert_safe_failure(self, result, out, err):
        self.assertNotEqual(result, 0)
        self.assertEqual(out, "")
        self.assertNotIn(PAT, err)
        self.assertNotIn(TOKEN, err)
        self.assertFalse(self.output.exists())

    def test_help_is_available_without_secret_files(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True, timeout=5
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--pat-file", result.stdout)

    def test_invalid_command_line_does_not_echo_argument_values(self):
        module = self.load()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = module.main(["--unexpected", PAT, TOKEN])
        self.assert_safe_failure(result, stdout.getvalue(), stderr.getvalue())

    def test_creates_private_token_and_only_prints_metadata(self):
        result, out, err, opener, _ = self.invoke()
        self.assertEqual(result, 0, err)
        self.assertEqual(self.output.read_bytes(), TOKEN.encode("ascii"))
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        self.assertEqual(self.output.stat().st_uid, os.getuid())
        self.assertEqual(json.loads(out), {"path": str(self.output), "expires_at": EXPIRY})
        self.assertEqual(err, "")
        self.assertNotIn(PAT, out)
        self.assertNotIn(TOKEN, out)
        self.assertEqual(opener.open.call_count, 1)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["pat", "registration"])

    def test_fractional_expiry_is_conservatively_normalized(self):
        response = Response(body=json.dumps({
            "token": TOKEN, "expires_at": "2026-10-02T13:00:00.9876543Z"
        }).encode())
        result, out, err, opener, _ = self.invoke(response=response)
        self.assertEqual(result, 0, err)
        self.assertEqual(json.loads(out)["expires_at"], EXPIRY)
        self.assertEqual(self.output.read_bytes(), TOKEN.encode("ascii"))
        self.assertEqual(opener.open.call_count, 1)

    def test_numeric_offset_expiry_returns_the_same_utc_instant_without_extension(self):
        for value in ["2026-10-02T13:00:00+00:00", "2026-10-02T16:00:00+03:00",
                      "2026-10-02T08:00:00-05:00", "2026-10-02T13:00:00.987654321+00:00"]:
            with self.subTest(expiry=value):
                self.output.unlink(missing_ok=True)
                response = Response(body=json.dumps({"token": TOKEN, "expires_at": value}).encode())
                result, out, err, opener, _ = self.invoke(response=response)
                self.assertEqual(result, 0, err)
                self.assertEqual(json.loads(out)["expires_at"], EXPIRY)
                self.assertEqual(self.output.read_bytes(), TOKEN.encode("ascii"))
                self.assertEqual(opener.open.call_count, 1)
                self.assertNotIn(TOKEN, out + err)

    def test_unknown_or_malformed_numeric_offset_never_publishes_a_token(self):
        for value in ["2026-10-02T13:00:00-00:00", "2026-10-02T13:00:00+00:60",
                      "2026-10-02T13:00:00+24:00", "2026-10-02T13:00:00+01:99",
                      "2026-10-02T13:00:00+0000", "2026-10-02T13:00:00+00"]:
            with self.subTest(expiry=value):
                response = Response(body=json.dumps({"token": TOKEN, "expires_at": value}).encode())
                result, out, err, opener, _ = self.invoke(response=response)
                self.assert_safe_failure(result, out, err)
                self.assertEqual(opener.open.call_count, 1)

    def test_numeric_offsets_preserve_future_and_one_hour_ttl_rules(self):
        for value in ["2026-10-02T16:00:01+03:00", "2026-10-02T15:00:00+03:00",
                      "2026-10-02T14:59:59.999999+03:00"]:
            with self.subTest(expiry=value):
                response = Response(body=json.dumps({"token": TOKEN, "expires_at": value}).encode())
                result, out, err, opener, _ = self.invoke(response=response)
                self.assert_safe_failure(result, out, err)
                self.assertEqual(opener.open.call_count, 1)

    def test_numeric_offset_does_not_bypass_local_issuer_clock_admission(self):
        response = Response(body=json.dumps({
            "token": TOKEN, "expires_at": "2026-10-02T15:30:00+03:00"
        }).encode())
        response.headers["Date"] = "Fri, 02 Oct 2026 12:00:06 GMT"
        result, out, err, opener, _ = self.invoke(response=response)
        self.assert_safe_failure(result, out, err)
        self.assertEqual(opener.open.call_count, 1)

    def test_numeric_offset_duplicate_expiry_key_is_rejected(self):
        response = Response(body=json.dumps({
            "token": TOKEN, "expires_at": "2026-10-02T16:00:00+03:00"
        }).encode()[:-1] + b',"expires_at":"2026-10-02T13:00:00Z"}')
        result, out, err, opener, _ = self.invoke(response=response)
        self.assert_safe_failure(result, out, err)
        self.assertEqual(opener.open.call_count, 1)

    def test_verified_http_issuer_clock_bounds_one_hour_ttl(self):
        response = Response(body=json.dumps({
            "token": TOKEN, "expires_at": "2026-10-02T13:00:01.123Z"
        }).encode())
        response.headers["Date"] = "Fri, 02 Oct 2026 12:00:01 GMT"
        result, out, err, opener, _ = self.invoke(response=response)
        self.assertEqual(result, 0, err)
        self.assertEqual(json.loads(out)["expires_at"], "2026-10-02T13:00:01Z")
        self.assertEqual(opener.open.call_count, 1)

    def test_rejects_missing_invalid_or_skewed_issuer_date(self):
        for value in [None, "invalid", "Fri, 02 Oct 2026 12:01:00 GMT",
                      "Fri, 02 Oct 2026 11:59:00 GMT"]:
            with self.subTest(date=value):
                self.output.unlink(missing_ok=True)
                response = Response()
                response.headers = {"Date": value}
                result, out, err, opener, _ = self.invoke(response=response)
                self.assert_safe_failure(result, out, err)
                self.assertEqual(opener.open.call_count, 1)

    def test_request_uses_post_fixed_endpoint_headers_and_finite_timeout(self):
        _, _, _, opener, _ = self.invoke()
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url,
                         "https://api.github.com/repos/Afonenko-QCL-NEGF/qcl-negf/actions/runners/registration-token")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.data, b"{}")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + PAT)
        self.assertEqual(request.get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(request.get_header("X-github-api-version"), "2022-11-28")
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 30)

    def test_transport_disables_proxies_redirects_and_uses_verified_tls(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://untrusted.invalid:1234"}):
            _, _, _, _, builder = self.invoke()
        handlers = builder.call_args.args
        proxy = next(h for h in handlers if isinstance(h, urllib.request.ProxyHandler))
        tls = next(h for h in handlers if isinstance(h, urllib.request.HTTPSHandler))
        redirect = next(h for h in handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
        self.assertEqual(proxy.proxies, {})
        self.assertTrue(tls._context.check_hostname)
        self.assertEqual(tls._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertIsNone(redirect.redirect_request(None, None, 302, "redirect", {},
                                                   "https://evil.invalid/"))

    def test_valid_explicit_repository_selects_only_github_api_path(self):
        _, _, _, opener, _ = self.invoke(repository="example-owner/example.repo")
        self.assertEqual(opener.open.call_args.args[0].full_url,
                         "https://api.github.com/repos/example-owner/example.repo/actions/runners/registration-token")

    def test_rejects_repository_injection_before_http(self):
        for repository in ["../repo", "owner/repo/extra", "owner/repo?x=y", "https://evil.invalid/repo",
                           "owner/-", "owner/..", "-owner/repo", "owner/repo\n"]:
            with self.subTest(repository=repository):
                result, out, err, opener, _ = self.invoke(repository=repository)
                self.assert_safe_failure(result, out, err)
                opener.open.assert_not_called()

    def test_rejects_pat_modes_before_http(self):
        for mode in [0o400, 0o640, 0o644, 0o700]:
            with self.subTest(mode=mode):
                self.pat_file.chmod(mode)
                result, out, err, opener, _ = self.invoke()
                self.assert_safe_failure(result, out, err)
                opener.open.assert_not_called()

    def test_rejects_foreign_pat_owner_before_http(self):
        module = self.load()
        actual_uid = os.getuid()
        with mock.patch.object(module.os, "getuid", return_value=actual_uid + 1):
            result, out, err, opener, _ = self.invoke()
        self.assert_safe_failure(result, out, err)
        opener.open.assert_not_called()

    def test_rejects_pat_size_whitespace_and_invalid_prefixes(self):
        for value in [PAT + "\n", PAT + "\r", PAT + " ", "" , "secret", "ghp_abc",
                      "ghp_" + "a" * 16384, "github_pat_" + "a" * 16384]:
            with self.subTest(length=len(value)):
                self.pat_file.write_text(value)
                result, out, err, opener, _ = self.invoke()
                self.assert_safe_failure(result, out, err)
                opener.open.assert_not_called()

    def test_accepts_fine_grained_pat_prefix(self):
        fine_pat = "github_pat_" + "a" * 22 + "_" + "b" * 59
        self.pat_file.write_text(fine_pat)
        result, out, err, opener, _ = self.invoke()
        self.assertEqual(result, 0, err)
        self.assertEqual(opener.open.call_args.args[0].get_header("Authorization"), "Bearer " + fine_pat)
        self.assertNotIn(fine_pat, out + err)

    def test_rejects_pat_symlink_directory_and_symlink_parent(self):
        original = self.root / "actual-pat"
        self.pat_file.rename(original)
        self.pat_file.symlink_to(original)
        result, out, err, opener, _ = self.invoke()
        self.assert_safe_failure(result, out, err)
        opener.open.assert_not_called()
        self.pat_file.unlink()
        self.pat_file.mkdir()
        self.pat_file.chmod(0o600)
        result, out, err, opener, _ = self.invoke()
        self.assert_safe_failure(result, out, err)
        opener.open.assert_not_called()
        self.pat_file = self.root / "linked-dir" / "actual-pat"
        (self.root / "linked-dir").symlink_to(self.root, target_is_directory=True)
        result, out, err, opener, _ = self.invoke()
        self.assert_safe_failure(result, out, err)
        opener.open.assert_not_called()

    def test_existing_output_is_never_overwritten_or_requested(self):
        self.output.write_text("existing")
        result, out, err, opener, _ = self.invoke()
        self.assertNotEqual(result, 0)
        self.assertEqual(out, "")
        self.assertEqual(self.output.read_text(), "existing")
        opener.open.assert_not_called()

    def test_rejects_output_symlink_and_symlink_parent_before_http(self):
        target = self.root / "existing"
        target.write_text("existing")
        self.output.symlink_to(target)
        result, out, err, opener, _ = self.invoke()
        self.assertNotEqual(result, 0)
        self.assertEqual(target.read_text(), "existing")
        opener.open.assert_not_called()
        self.output.unlink()
        link = self.root / "linked-dir"
        link.symlink_to(self.root, target_is_directory=True)
        self.output = link / "registration"
        result, out, err, opener, _ = self.invoke()
        self.assert_safe_failure(result, out, err)
        opener.open.assert_not_called()

    def test_atomic_publish_race_never_overwrites_and_removes_temporary_file(self):
        module = self.load()
        original_link = module.os.link
        def race(source, destination, **kwargs):
            self.output.write_text("raced")
            return original_link(source, destination, **kwargs)
        with mock.patch.object(module.os, "link", side_effect=race):
            result, out, err, opener, _ = self.invoke()
        self.assertNotEqual(result, 0)
        self.assertEqual(out, "")
        self.assertEqual(self.output.read_text(), "raced")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["pat", "registration"])
        self.assertEqual(opener.open.call_count, 1)
        self.assertNotIn(PAT, err)
        self.assertNotIn(TOKEN, err)

    def test_http_errors_print_status_only_without_retry_or_body(self):
        error = urllib.error.HTTPError("https://api.github.com/", 403, PAT, {"secret": PAT},
                                       io.BytesIO(TOKEN.encode()))
        result, out, err, opener, _ = self.invoke(error=error)
        self.assert_safe_failure(result, out, err)
        self.assertIn("403", err)
        self.assertEqual(opener.open.call_count, 1)

    def test_non_created_and_redirect_responses_are_errors_without_output(self):
        for status in [200, 301, 302, 307, 308]:
            with self.subTest(status=status):
                result, out, err, opener, _ = self.invoke(response=Response(status=status))
                self.assert_safe_failure(result, out, err)
                self.assertIn(str(status), err)
                self.assertEqual(opener.open.call_count, 1)

    def test_transport_error_is_sanitized_and_not_retried(self):
        error = urllib.error.URLError(PAT + TOKEN)
        result, out, err, opener, _ = self.invoke(error=error)
        self.assert_safe_failure(result, out, err)
        self.assertIn("outcome", err)
        self.assertEqual(opener.open.call_count, 1)

    def test_unexpected_transport_exception_is_sanitized_and_not_retried(self):
        result, out, err, opener, _ = self.invoke(error=RuntimeError(PAT + TOKEN))
        self.assert_safe_failure(result, out, err)
        self.assertEqual(opener.open.call_count, 1)

    def test_response_size_is_bounded_and_oversize_rejected(self):
        response = Response(body=b"x" * (65536 + 1))
        result, out, err, _, _ = self.invoke(response=response)
        self.assert_safe_failure(result, out, err)
        self.assertEqual(response.read_limits, [65537])

    def test_rejects_bad_schema_tokens_and_expiry_without_exposing_body(self):
        values = [
            {}, [], {"token": TOKEN}, {"expires_at": EXPIRY},
            {"token": None, "expires_at": EXPIRY},
            {"token": "short", "expires_at": EXPIRY},
            {"token": TOKEN + "\n", "expires_at": EXPIRY},
            {"token": TOKEN, "expires_at": "garbage"},
            {"token": TOKEN, "expires_at": "2026-10-02T13:00:00"},
            {"token": TOKEN, "expires_at": "2026-10-02T12:00:00Z"},
            {"token": TOKEN, "expires_at": "2026-10-02T11:59:59Z"},
            {"token": TOKEN, "expires_at": "2026-10-02T13:00:01Z"},
        ]
        for value in values:
            with self.subTest(value=value):
                result, out, err, _, _ = self.invoke(response=Response(body=json.dumps(value).encode()))
                self.assert_safe_failure(result, out, err)

    def test_rejects_invalid_json_and_duplicate_keys(self):
        for body in [b"not JSON " + PAT.encode(), b"\xff",
                     json.dumps({"token": TOKEN, "expires_at": EXPIRY}).encode()[:-1] +
                     b',"token":"' + TOKEN.encode() + b'"}']:
            with self.subTest(body_kind=body[:2]):
                result, out, err, _, _ = self.invoke(response=Response(body=body))
                self.assert_safe_failure(result, out, err)


if __name__ == "__main__":
    unittest.main()
