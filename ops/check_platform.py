"""Explicit App/Ops test domains; never prepares packages or a live backend."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

APP_FILES = (
    "tests/test_native_attempt.py", "tests/test_bootstrap_profile.py",
    "tests/test_application_path.py", "tests/test_registration.py",
    "tests/test_runtime_bindings.py",
)
ENTRY_OPT_IN = "tests/test_host_resource_client.py::test_generated_entries_select_only_nixos_privileged_sudo"
ENTRY_REASON = "Set QCL_TEST_HOST_RESOURCE_ENTRY_BUILD=1 for the source-package build"
ENTRY_GATE = "Explicit prepared Ops Python: QCL_TEST_HOST_RESOURCE_ENTRY_BUILD=1 pytest -q " + ENTRY_OPT_IN
OPS_ENV = (
    "GI_TYPELIB_PATH", "QCL_TEST_ANSIBLE_COLLECTIONS", "ANSIBLE_COLLECTIONS_PATH",
    "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH", "QCL_TEST_PYTHON_BASE", "QCL_TEST_PYTHON_LAUNCHER",
    "QCL_TEST_ANSIBLE_ENGINE_OUTPUT", "QCL_TEST_ANSIBLE_ENGINE_ROOT", "QCL_TEST_ANSIBLE_ENGINE_VERSION",
)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def file_of(node):
    path = node.split("::", 1)[0]
    need(path.startswith("tests/") and path.endswith(".py")
         and all(p not in ("", ".", "..") for p in path.split("/")), "nonrelative test node")
    return path


def collection(text):
    rows = [line.strip() for line in text.splitlines() if "::" in line]
    for node in rows:
        file_of(node)
    count = re.findall(r"(?m)^([0-9]+) tests? collected(?: in .*)?$", text)
    need(rows and len(rows) == len(set(rows)) and len(count) == 1
         and int(count[0]) == len(rows), "empty/duplicate/incomplete collection")
    return rows


def partition(canonical, app, ops):
    for rows in (canonical, app, ops):
        need(rows and len(rows) == len(set(rows)), "empty/duplicate test domain")
        for node in rows:
            file_of(node)
    expected = [n for n in canonical if file_of(n) in APP_FILES]
    need(set(file_of(n) for n in expected) == set(APP_FILES)
         and Counter(app) == Counter(expected) and not set(app) & set(ops)
         and Counter(app) + Counter(ops) == Counter(canonical), "test domain gap/overlap/missing App file")
    return {"app": app, "ops": ops}


def summary(text):
    lines = [line.strip().strip("= ") for line in text.splitlines()
             if re.search(r"\bin [0-9.]+s(?: \([0-9:]+\))?$", line.strip())]
    need(len(lines) == 1, "missing/ambiguous pytest summary")
    line = lines[0]
    need(not re.search(r"\b[0-9]+ (?:failed|errors?|xfailed|xpassed|subtests? failed|subtests? skipped)\b", line),
         "pytest reported failed/unsupported outcome")
    values = {}
    for name in ("passed", "skipped", "subtests passed"):
        matches = re.findall(r"(?:^|, )([0-9]+) " + name + r"(?=,| in )", line)
        need(len(matches) <= 1, "duplicate pytest counter")
        values[name] = int(matches[0]) if matches else 0
    need(values["passed"] + values["skipped"] > 0, "no parent outcomes")
    return values


def junit_node(case):
    parts = case.attrib.get("classname", "").split(".")
    name = case.attrib.get("name", "")
    need(parts and parts[0] == "tests" and name, "foreign JUnit class/name")
    indices = [i for i, p in enumerate(parts) if p.startswith("test_")]
    need(indices, "missing JUnit module")
    i = indices[0]
    node = "/".join(parts[:i + 1]) + ".py::" + "::".join([*parts[i + 1:], name])
    file_of(node)
    return node


def junit(path, expected, stdout, domain):
    need(expected and len(expected) == len(set(expected)), "duplicate/empty expected parents")
    totals = summary(stdout)
    root = ET.parse(path).getroot()
    suites = root.findall("testsuite") if root.tag == "testsuites" else [root] if root.tag == "testsuite" else []
    need(len(suites) == 1, "one pytest suite required")
    suite = suites[0]; cases = suite.findall("testcase")
    need(int(suite.attrib.get("tests", "-1")) == len(cases) + totals["subtests passed"], "JUnit tests/subtest counter mismatch")
    groups = {node: [] for node in expected}; counts = {"errors": 0, "failures": 0, "skipped": 0}
    required = []; skips = []; nodes = []
    for case in cases:
        node = junit_node(case); flags = [k for k in ("error", "failure", "skipped") if case.find(k) is not None]
        need(len(flags) <= 1, "ambiguous JUnit outcome")
        if flags:
            counts[{"error": "errors", "failure": "failures", "skipped": "skipped"}[flags[0]]] += 1
        if node in groups:
            groups[node].append("parent"); nodes.append(node)
        else:
            # Older pytest may emit explicitly identified unittest subtest cases.
            matches = [p for p in expected if node.startswith(p + " (") and node.endswith(")")]
            need(not totals["subtests passed"] and len(matches) == 1, "unknown JUnit parent/subtest")
            groups[matches[0]].append("subtest")
        need(not any(k in flags for k in ("error", "failure")), "failed JUnit case")
        if "skipped" in flags:
            reason = case.find("skipped").attrib.get("message", "")
            need(domain == "ops" and node == ENTRY_OPT_IN and reason == ENTRY_REASON,
                 "unexplained skip/missing declared dependency")
            skips.append(node); required.append({"node": node, "reason": reason, "required_gate": ENTRY_GATE})
    need(all(types.count("parent") == 1 for types in groups.values()), "missing/duplicate parent or subtest-only coverage")
    need(all(int(suite.attrib.get(k, "-1")) == v for k, v in counts.items()), "JUnit outcome counter mismatch")
    need(totals["passed"] == len(expected) - len(skips) and totals["skipped"] == len(skips),
         "pytest parent summary mismatch")
    return {"parents": len(expected), "nodes": nodes, "skipped": skips,
            "explicit_subtest_cases": sum(v.count("subtest") for v in groups.values()),
            "framework_subtests_passed": totals["subtests passed"], "required_native_gates": required}


def environments(environ, work):
    common = {"PATH": environ.get("PATH", ""), "HOME": str(work / "home"), "TMPDIR": str(work),
              "LANG": "C.UTF-8", "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
              "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "NIX_CONFIG": "extra-experimental-features = nix-command flakes\n"}
    if "QCL_TEST_NIXPKGS" in environ:
        common["QCL_TEST_NIXPKGS"] = environ["QCL_TEST_NIXPKGS"]
    app = dict(common, AIIDA_PATH=str(work / "aiida-empty"))
    ops = dict(common, **{k: environ[k] for k in OPS_ENV if k in environ})
    return app, ops


def validate_preflight(value, domain):
    need(type(value) is dict and value.get("python") == [3, 14]
         and isinstance(value.get("pytest"), str) and value["pytest"].split(".")[0] in ("8", "9"),
         "declared Python3.14/pytest8-or9 required")
    if domain == "app":
        need(value.get("aiida") == "2.9.2" and value.get("portal") is True,
             "locked application AiiDA2.9.2 and Portal required")
    else:
        need(value.get("ansible") == "2.21.1" and value.get("gi") is True and value.get("pyarrow") is True,
             "declared Ops Ansible/GI/PyArrow dependencies required")
    return value


def validate_operands(scope, app_python, ops_python):
    need(scope in ("full", "ops"), "explicit full/ops scope required")
    need(os.getuid() == os.geteuid() and os.getuid() != 0, "nonroot test runner required")
    need(scope != "full" or app_python, "full check requires explicit application Python")
    for name, interpreter in [("operations", ops_python)] + ([("application", app_python)] if scope == "full" else []):
        need(isinstance(interpreter, str) and Path(interpreter).is_absolute(), "absolute declared " + name + " Python required")


def run_checks(source, scope, app_python, ops_python, output, *, environ=None, execute=subprocess.run):
    validate_operands(scope, app_python, ops_python)
    source = Path(source).resolve(strict=True); output = Path(output).absolute()
    need(source.is_dir() and not output.exists() and not output.is_symlink(), "existing source/new output required")
    output.mkdir(); records = []
    with tempfile.TemporaryDirectory(prefix="qcl-platform-check-") as temporary:
        work = Path(temporary); (work / "home").mkdir(); (work / "aiida-empty").mkdir()
        envs = dict(zip(("app", "ops"), environments(os.environ if environ is None else environ, work)))
        need(Path(envs["ops"].get("QCL_TEST_NIXPKGS", "")).is_absolute()
             and all(k in envs["ops"] for k in OPS_ENV), "prepared declared Ops environment/Nixpkgs required")
        py = {"app": app_python, "ops": ops_python}
        for domain in ("app", "ops"):
            if py[domain]:
                envs[domain]["PATH"] = str(Path(py[domain]).parent) + os.pathsep + envs[domain]["PATH"]

        def checked(label, argv, domain):
            out = output / (label + ".stdout"); err = output / (label + ".stderr")
            with out.open("xb") as stdout, err.open("xb") as stderr:
                result = execute(argv, cwd=source, env=envs[domain], stdin=subprocess.DEVNULL,
                                 stdout=stdout, stderr=stderr, check=False)
            records.append({"label": label, "argv": argv, "exit": result.returncode})
            need(out.stat().st_size <= 32 * 1024 * 1024 and err.stat().st_size <= 32 * 1024 * 1024,
                 "test output exceeds read budget; original files retained")
            if result.returncode != 0:
                sys.stdout.write(out.read_text()); sys.stderr.write(err.read_text())
                raise ValueError(label + " failed; retained stdout/stderr in " + str(output))
            return out.read_text()

        base = "import json,sys,pytest;v={'python':list(sys.version_info[:2]),'pytest':pytest.__version__};"
        preflights = {}
        for domain in (("app", "ops") if scope == "full" else ("ops",)):
            code = base + ("import importlib.metadata as m;from aiida.schedulers.plugins.slurm import SlurmScheduler;from qcl_negf_api.quantum_preview import runtime_context,ConfiguratorError;v.update(aiida=m.version('aiida-core'),portal=True);"
                           if domain == "app" else "import ansible,gi,pyarrow.parquet;gi.require_version('NM','1.0');from gi.repository import NM,GLib;v.update(ansible=ansible.__version__,gi=True,pyarrow=True);") + "print(json.dumps(v))"
            preflights[domain] = validate_preflight(json.loads(checked(domain + "-preflight", [py[domain], "-I", "-B", "-c", code], domain)), domain)
        ignore = ["--ignore=" + name for name in APP_FILES]

        def pytest(domain, label, targets, extra):
            return checked(label, [py[domain], "-I", "-B", "-m", "pytest", "-p", "no:cacheprovider",
                                   "--rootdir", str(source), "-q", *extra, *targets], domain)

        ops = collection(pytest("ops", "ops-collect", ["tests"], ["--collect-only", *ignore]))
        if scope == "full":
            canonical = collection(pytest("app", "canonical-collect", ["tests"], ["--collect-only"]))
            app = collection(pytest("app", "app-collect", list(APP_FILES), ["--collect-only"]))
            domains = partition(canonical, app, ops)
        else:
            need(not any(file_of(n) in APP_FILES for n in ops), "Ops-only collection includes App files")
            domains = {"ops": ops}
        outcomes = {}
        for domain, expected in domains.items():
            xml = output / (domain + ".xml")
            text = pytest(domain, domain + "-tests", list(APP_FILES) if domain == "app" else ["tests"],
                          ["--junitxml=" + str(xml), *([] if domain == "app" else ignore)])
            outcomes[domain] = junit(xml, expected, text, domain)
        gates = [g for row in outcomes.values() for g in row["required_native_gates"]]
        report = {"state": "CHECKED_FULL_DOMAINS_NATIVE_OPT_INS_REQUIRED" if scope == "full" and gates else
                  "CHECKED_FULL_TEST_DOMAINS_NOT_NATIVE_OR_SCIENCE" if scope == "full" else "CHECKED_OPS_ONLY_NOT_FULL_PLATFORM",
                  "scope": scope, "preflights": preflights, "collections": domains, "outcomes": outcomes,
                  "required_native_gates": gates, "commands": records, "scientific_acceptance": "not_measured"}
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", required=True, choices=("ops", "full"))
    parser.add_argument("--source", type=Path, default=Path.cwd())
    parser.add_argument("--application-python", default=os.environ.get("QCL_PLATFORM_APPLICATION_PYTHON"))
    parser.add_argument("--operations-python", default=os.environ.get("QCL_PLATFORM_OPERATIONS_PYTHON"))
    parser.add_argument("--output", type=Path, default=os.environ.get("QCL_PLATFORM_CHECK_OUTPUT"))
    args = parser.parse_args(argv)
    validate_operands(args.scope, args.application_python, args.operations_python)
    if args.output is None:
        args.output = Path(tempfile.mkdtemp(prefix="qcl-platform-report-")) / "result"
        print("Report directory: " + str(args.output), file=sys.stderr)
    report = run_checks(args.source, args.scope, args.application_python, args.operations_python, args.output)
    print(json.dumps({k: v for k, v in report.items() if k not in ("collections", "commands")}))


if __name__ == "__main__":
    main()
