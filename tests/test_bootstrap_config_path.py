"""Read real files through the bootstrap reader; never create an AiiDA profile/job."""
import json
from pathlib import Path
import subprocess

import pytest


def profile():
    return {"profiles": {"qcl-negf": {
        "storage": {"backend": "core.psql_dos", "config": {
            "database_hostname": "/run/postgresql", "database_port": 5432,
            "database_username": "qcl-negf", "database_password": "",
            "database_name": "qcl-negf",
            "repository_uri": "file:///var/lib/qcl-negf/aiida/repository",
        }}, "process_control": {"backend": "core.zeromq"},
    }}}


@pytest.mark.parametrize("case", ["matching", "missing", "invalid", "incompatible"])
def test_bootstrap_reads_aiida_configuration_directory_not_identity_root(tmp_path, case):
    base = tmp_path / "aiida"
    nested = base / ".aiida"
    nested.mkdir(parents=True)
    # A root-level decoy must never hide a missing/invalid/incompatible real config.
    (base / "config.json").write_text(json.dumps(profile()))
    if case == "matching":
        (base / "config.json").write_text("invalid root-level decoy")
        (nested / "config.json").write_text(json.dumps(profile()))
    elif case == "invalid":
        (nested / "config.json").write_text("invalid actual configuration")
    elif case == "incompatible":
        value = profile()
        value["profiles"]["qcl-negf"]["storage"]["config"]["repository_uri"] = "file:///different"
        (nested / "config.json").write_text(json.dumps(value))
    source = (Path(__file__).parents[1] / "ops/bootstrap.ts").as_uri()
    driver = tmp_path / "read.ts"
    driver.write_text(f'import {{ readExistingConfiguration, profileSetupRequired }} from {json.dumps(source)};\n'
                      'const value = await readExistingConfiguration(Deno.args[0]!);\n'
                      'console.log(JSON.stringify({ setupRequired: profileSetupRequired(value) }));\n')
    result = subprocess.run(["deno", "run", f"--allow-read={base}", str(driver), str(base)],
                            capture_output=True, text=True, timeout=30)
    if case == "matching":
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"setupRequired": False}
    else:
        assert result.returncode != 0
        expected = {"missing": "NotFound", "invalid": "SyntaxError",
                    "incompatible": "differs from the declared"}[case]
        assert expected in result.stderr
