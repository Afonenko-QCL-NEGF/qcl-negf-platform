"""Evaluate owning wrapper text, then exercise its Slurm child environment."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


class ReleaseSlurmEnvironmentTests(unittest.TestCase):
    def test_both_operational_wrappers_supply_daemons_declared_slurm_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw-slurm"
            raw.mkdir()
            conf = root / "slurm.conf"
            conf.write_text("ClusterName=fixture\n")
            queue = raw / "squeue"
            queue.write_text('#!/bin/sh\ntest "$SLURM_CONF" = "$EXPECTED_CONFIG" && test -r "$SLURM_CONF"\n')
            queue.chmod(0o755)
            operations = root / "operations" / "ops"
            operations.mkdir(parents=True)
            for name in ("application_release.py", "worker_lifecycle.py"):
                (operations / name).write_text("import subprocess\nraise SystemExit(subprocess.call(['squeue']))\n")
            module = Path(__file__).parents[1] / "modules" / "release.nix"
            # Pure module boundary: no nixpkgs fetch, derivation build or services.
            expression = '''let
              module = import MODULE {
                config = {
                  qclNegf.release = { enable = true; applicationPackage = null; };
                  qclNegf.cluster = { controller = true; worker = false; solverPackage = null; };
                  qclNegf.application = { enable = false; bootstrap.email = "fixture@example.invalid"; api.allowedCodesFile = null; };
                  services.slurm.etcSlurm = CONFIGDIR;
                };
                lib = {
                  mkIf = condition: value: if condition then value else {};
                  mkMerge = builtins.foldl' (a: b: a // b) {};
                };
                pkgs = {
                  runCommand = name: attrs: script: OPERATIONS;
                  writeShellApplication = args: args;
                };
              };
              in builtins.map (p: { inherit (p) name text; }) module.config.environment.systemPackages
            '''.replace("MODULE", str(module)).replace("CONFIGDIR", json.dumps(str(root))).replace("OPERATIONS", json.dumps(str(operations.parent)))
            evaluated = subprocess.run(["nix-instantiate", "--eval", "--strict", "--json", "--expr", expression], capture_output=True, text=True, timeout=10)
            self.assertEqual(evaluated.returncode, 0, evaluated.stderr)
            wrappers = json.loads(evaluated.stdout)
            self.assertEqual({p["name"] for p in wrappers}, {"qcl-negf-release", "qcl-negf-worker-lifecycle"})
            import os
            environment = dict(os.environ, PATH=str(raw) + os.pathsep + os.environ["PATH"], EXPECTED_CONFIG=str(conf))
            environment.pop("SLURM_CONF", None)
            for wrapper in wrappers:
                with self.subTest(command=wrapper["name"]):
                    result = subprocess.run(["/bin/sh", "-c", wrapper["text"]], env=environment, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
