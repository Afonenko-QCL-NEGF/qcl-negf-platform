"""Public two-domain contract tests; no package install or real backend."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).parents[1] / "ops/check_platform.py"


def module():
    assert SCRIPT.is_file(), "full public check lacks an explicit two-domain dependency gate"
    spec = importlib.util.spec_from_file_location("public_platform_check", SCRIPT)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def node_files(m):
    return [name + "::test_required" for name in m.APP_FILES]


class PublicCheck(unittest.TestCase):
    def test_full_missing_app_fails_before_any_child_or_output(self):
        m = module()
        calls = []
        with tempfile.TemporaryDirectory() as tmp, patch.object(m.os, "getuid", return_value=1000), patch.object(m.os, "geteuid", return_value=1000):
            root = Path(tmp); out = root / "result"
            with self.assertRaisesRegex(ValueError, "application Python"):
                m.run_checks(root, "full", None, "/declared/ops/python", out,
                             execute=lambda *a, **k: calls.append(a))
            self.assertEqual(calls, []); self.assertFalse(out.exists())

    def test_root_user_relative_interpreters_and_unknown_scope_fail_before_child(self):
        m = module()
        for uid, scope, app, ops in [(0, "full", "/app/python", "/ops/python"), (1000, "unknown", "/app/python", "/ops/python"), (1000, "full", "python3", "/ops/python"), (1000, "ops", None, "python3")]:
            calls = []
            with tempfile.TemporaryDirectory() as tmp, patch.object(m.os, "getuid", return_value=uid), patch.object(m.os, "geteuid", return_value=uid):
                with self.subTest(uid=uid, scope=scope), self.assertRaises(ValueError):
                    m.run_checks(Path(tmp), scope, app, ops, Path(tmp) / "out", execute=lambda *a, **k: calls.append(a))
                self.assertEqual(calls, [])

    def test_exact_whole_domains_and_new_remaining_file(self):
        m = module(); app = node_files(m); ops = ["tests/test_new.py::test_new"]
        self.assertEqual(m.partition(app + ops, app, ops), {"app": app, "ops": ops})
        for a, b, c in [(app + ops, app, []), (app + ops, app + [ops[0]], ops), (app + ops, app[:-1], ops), (app + ops, app, ops * 2), (app + ops, app, ["tests/test_foreign.py::test_x"])]:
            with self.assertRaises(ValueError): m.partition(a, b, c)

    def test_portal_runtime_fixture_is_whole_app_domain_and_required_dependency(self):
        m = module()
        portal = "tests/test_runtime_bindings.py"
        self.assertIn(portal, m.APP_FILES)
        self.assertEqual(len(m.APP_FILES), 5)
        app = node_files(m); ops = ["tests/test_other.py::test_ok"]
        old_app = [n for n in app if m.file_of(n) != portal]
        with self.assertRaisesRegex(ValueError, "gap/overlap"):
            m.partition(app + ops, old_app, ops + [n for n in app if m.file_of(n) == portal])
        with self.assertRaises(ValueError):
            m.validate_preflight({"python": [3, 14], "pytest": "8.4.2", "aiida": "2.9.2"}, "app")
        m.validate_preflight({"python": [3, 14], "pytest": "8.4.2", "aiida": "2.9.2", "portal": True}, "app")

    def test_collection_rejects_absolute_foreign_duplicate_and_count_mismatch(self):
        m = module(); good = "tests/test_x.py::test_a\n\n1 test collected in 0.01s\n"
        self.assertEqual(m.collection(good), ["tests/test_x.py::test_a"])
        for value in (good.replace("tests/", "/source/tests/"), good.replace("1 test", "2 tests"), good.replace("\n\n", "\ntests/test_x.py::test_a\n\n"), ""):
            with self.assertRaises(ValueError): m.collection(value)

    def xml(self, tmp, cases, total=None, skipped=0, failures=0):
        path = Path(tmp) / "cases.xml"
        path.write_text(f'<testsuites><testsuite tests="{total if total is not None else len(cases)}" errors="0" failures="{failures}" skipped="{skipped}">' + "".join(cases) + "</testsuite></testsuites>")
        return path

    def test_parent_coverage_and_pytest9_positive_subtests_are_distinct(self):
        m = module(); case = '<testcase classname="tests.test_x.Case" name="test_a[p]"/>'
        with tempfile.TemporaryDirectory() as tmp:
            p = self.xml(tmp, [case], total=3)
            result = m.junit(p, ["tests/test_x.py::Case::test_a[p]"], "1 passed, 2 subtests passed in 0.1s\n", "ops")
            self.assertEqual(result["parents"], 1); self.assertEqual(result["framework_subtests_passed"], 2)
            for cases, total, text in [([case, case], 2, "2 passed in 0.1s\n"), ([case], 2, "1 passed in 0.1s\n"), ([case.replace("tests.", "foreign.")], 1, "1 passed in 0.1s\n"), ([case.replace("test_a[p]", "test_a[p] (x=1)")], 1, "1 passed in 0.1s\n")]:
                with self.assertRaises(ValueError): m.junit(self.xml(tmp, cases, total), ["tests/test_x.py::Case::test_a[p]"], text, "ops")

    def test_only_exact_named_opt_in_skip_and_reason_is_disclosed_not_native_pass(self):
        m = module(); node = "tests/test_host_resource_client.py::test_generated_entries_select_only_nixos_privileged_sudo"
        reason = "Set QCL_TEST_HOST_RESOURCE_ENTRY_BUILD=1 for the source-package build"
        case = '<testcase classname="tests.test_host_resource_client" name="test_generated_entries_select_only_nixos_privileged_sudo"><skipped type="pytest.skip" message="' + reason + '"/></testcase>'
        with tempfile.TemporaryDirectory() as tmp:
            p = self.xml(tmp, [case], skipped=1)
            r = m.junit(p, [node], "1 skipped in 0.1s\n", "ops")
            self.assertEqual(r["skipped"], [node]); self.assertEqual(len(r["required_native_gates"]), 1)
            for domain, bad in [("app", case), ("ops", case.replace(reason, "dependency missing")), ("ops", case.replace("test_generated_entries_select_only_nixos_privileged_sudo", "test_other"))]:
                with self.assertRaises(ValueError): m.junit(self.xml(tmp, [bad], skipped=1), [node], "1 skipped in 0.1s\n", domain)

    def test_no_dependency_skip_or_failed_subtest_can_be_accepted(self):
        m = module(); case = '<testcase classname="tests.test_x" name="test_a"><skipped message="optional PyArrow export dependency is not installed"/></testcase>'
        with tempfile.TemporaryDirectory() as tmp:
            for text in ("1 skipped in 0.1s\n", "1 passed, 1 subtests failed in 0.1s\n", "1 passed in 0.1s\n1 passed in 0.2s\n"):
                with self.assertRaises(ValueError): m.junit(self.xml(tmp, [case], skipped=1), ["tests/test_x.py::test_a"], text, "ops")

    def test_child_environments_do_not_mix_python_paths_or_ambient_profiles(self):
        m = module()
        source = {"PATH": "/declared/tools", "PYTHONPATH": "/foreign", "PYTHONHOME": "/foreign", "AIIDA_PATH": "/old/profile", "GI_TYPELIB_PATH": "/declared/gi", "QCL_TEST_NIXPKGS": "/locked/nixpkgs", "ANSIBLE_COLLECTIONS_PATH": "/declared/collections"}
        with tempfile.TemporaryDirectory() as tmp:
            app, ops = m.environments(source, Path(tmp))
            for row in (app, ops):
                self.assertNotIn("PYTHONPATH", row); self.assertNotIn("PYTHONHOME", row); self.assertEqual(row["PYTHONNOUSERSITE"], "1"); self.assertNotEqual(row.get("AIIDA_PATH"), "/old/profile")
            self.assertNotIn("GI_TYPELIB_PATH", app); self.assertEqual(ops["GI_TYPELIB_PATH"], "/declared/gi"); self.assertEqual(ops["ANSIBLE_COLLECTIONS_PATH"], "/declared/collections")

    def test_missing_app_or_required_arrow_preflight_is_failure_not_skip(self):
        m = module()
        for domain, raw in [("app", {"python": [3, 14], "pytest": "8.4.2", "aiida": "missing"}), ("ops", {"python": [3, 14], "pytest": "9.0.3", "ansible": "2.21.1", "gi": True, "pyarrow": False})]:
            with self.assertRaises(ValueError): m.validate_preflight(raw, domain)

    def test_full_pipeline_exact_domains_no_bootstrap_or_path_mixing(self):
        m = module(); calls = []; app = node_files(m)
        opt = "tests/test_host_resource_client.py::test_generated_entries_select_only_nixos_privileged_sudo"
        ops = ["tests/test_other.py::test_ok", opt]
        def collected(rows): return "\n".join(rows) + f"\n\n{len(rows)} tests collected in 0.01s\n"
        def execute(argv, **kw):
            calls.append((argv, kw["env"])); label = Path(kw["stdout"].name).stem
            if label == "app-preflight": value = json.dumps({"python": [3, 14], "pytest": "8.4.2", "aiida": "2.9.2", "portal": True})
            elif label == "ops-preflight": value = json.dumps({"python": [3, 14], "pytest": "9.0.3", "ansible": "2.21.1", "gi": True, "pyarrow": True})
            elif label == "canonical-collect": value = collected(app + ops)
            elif label == "app-collect": value = collected(app)
            elif label == "ops-collect": value = collected(ops)
            else:
                rows = app if label == "app-tests" else ops; cases = []
                for node in rows:
                    file, name = node.split("::"); cls = file[:-3].replace("/", ".")
                    child = '<skipped message="' + m.ENTRY_REASON + '"/>' if node == opt else ""
                    cases.append(f'<testcase classname="{cls}" name="{name}">{child}</testcase>')
                xml = Path(next(a.split("=", 1)[1] for a in argv if a.startswith("--junitxml=")))
                xml.write_text(f'<testsuites><testsuite tests="{len(rows)}" failures="0" errors="0" skipped="{1 if opt in rows else 0}">' + "".join(cases) + '</testsuite></testsuites>')
                value = f"{len(app)} passed in 0.01s\n" if label == "app-tests" else "1 passed, 1 skipped in 0.01s\n"
            kw["stdout"].write(value.encode())
            return type("Result", (), {"returncode": 0})()
        env = {k: "/declared/public" for k in m.OPS_ENV}
        env.update(PATH="/tools", QCL_TEST_NIXPKGS="/locked/nixpkgs", PYTHONPATH="/poison", QCL_TEST_HOST_RESOURCE_ENTRY_BUILD="1")
        with tempfile.TemporaryDirectory() as tmp, patch.object(m.os, "getuid", return_value=1000), patch.object(m.os, "geteuid", return_value=1000):
            root = Path(tmp); result = m.run_checks(root, "full", "/app/python", "/ops/python", root / "out", environ=env, execute=execute)
            self.assertEqual(result["collections"], {"app": app, "ops": ops}); self.assertEqual(result["state"], "CHECKED_FULL_DOMAINS_NATIVE_OPT_INS_REQUIRED")
            self.assertEqual(len(result["required_native_gates"]), 1)
        self.assertTrue(calls)
        for argv, child in calls:
            self.assertIn(argv[0], ("/app/python", "/ops/python")); self.assertNotIn("PYTHONPATH", child)
            self.assertNotIn("QCL_TEST_HOST_RESOURCE_ENTRY_BUILD", child)
            self.assertEqual(child["PATH"].split(os.pathsep)[0], str(Path(argv[0]).parent))
            if "pytest" in argv: self.assertIn("--rootdir", argv)

    def test_full_cli_missing_app_has_no_report_side_effect(self):
        m = module()
        with patch.dict(m.os.environ, {}, clear=True), patch.object(m.os, "getuid", return_value=1000), patch.object(m.os, "geteuid", return_value=1000), patch.object(m.tempfile, "mkdtemp", side_effect=AssertionError("must reject first")):
            with self.assertRaisesRegex(ValueError, "application Python"):
                m.main(["--scope", "full", "--operations-python", "/ops/python"])

    def test_actual_pytest_skip_reason_matches_named_contract(self):
        m = module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "tests").mkdir()
            name = "test_generated_entries_select_only_nixos_privileged_sudo"
            (root / "tests/test_host_resource_client.py").write_text("import pytest\ndef " + name + "():\n    pytest.skip(" + repr(m.ENTRY_REASON) + ")\n")
            xml = root / "result.xml"
            r = subprocess.run([sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", "--rootdir", str(root), "--junitxml=" + str(xml), "-q", "tests"], cwd=root, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"), capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            result = m.junit(xml, [m.ENTRY_OPT_IN], r.stdout, "ops")
            self.assertEqual(result["skipped"], [m.ENTRY_OPT_IN])

    def test_actual_unittest_subtests_preserve_parent_and_failure_is_not_success(self):
        m = module()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root / "tests").mkdir()
            test = root / "tests/test_subtests.py"
            source = "import unittest\nclass Case(unittest.TestCase):\n    def test_rows(self):\n        for n in (1, 2):\n            with self.subTest(n=n): self.assertGreater(n, 0)\n"
            test.write_text(source)
            env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
            xml = root / "result.xml"
            argv = [sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", "--rootdir", str(root), "--junitxml=" + str(xml), "-q", "tests"]
            good = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(good.returncode, 0, good.stderr)
            result = m.junit(xml, ["tests/test_subtests.py::Case::test_rows"], good.stdout, "ops")
            self.assertEqual(result["parents"], 1)
            if m.summary(good.stdout)["subtests passed"]:
                self.assertEqual(result["framework_subtests_passed"], 2)
            test.write_text(source.replace("(1, 2)", "(1, -2)"))
            bad = subprocess.run(argv, cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
            with self.assertRaises(ValueError):
                m.junit(xml, ["tests/test_subtests.py::Case::test_rows"], bad.stdout, "ops")

    def test_actual_pytest_rootdir_addresses_stable_across_two_sources(self):
        m = module(); addresses = []
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("first", "other-source"):
                root = Path(tmp) / name; (root / "tests").mkdir(parents=True)
                (root / "tests/test_address.py").write_text("def test_ok():\n    assert True\n")
                report = root / "result.xml"
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
                result = subprocess.run([sys.executable, "-B", "-m", "pytest", "-p", "no:cacheprovider", "--rootdir", str(root), "--junitxml=" + str(report), "-q", "tests"], cwd=root, env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                parsed = m.junit(report, ["tests/test_address.py::test_ok"], result.stdout, "ops")
                addresses.append(parsed["nodes"])
        self.assertEqual(addresses, [["tests/test_address.py::test_ok"], ["tests/test_address.py::test_ok"]])


if __name__ == "__main__": unittest.main(verbosity=2)
