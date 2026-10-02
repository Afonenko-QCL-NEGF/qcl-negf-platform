"""Read-only guard before changing temporary bootstrap VM kernel arguments."""
import re
import subprocess
import sys


def validate_bootstrap(config, expected_args):
    properties = dict(line.split(": ", 1) for line in config.splitlines() if ": " in line)
    if (properties.get("name") != "qcl-bootstrap"
            or set(properties.get("tags", "").split(";")) != {"qcl-negf", "bootstrap"}
            or properties.get("protection", "0") != "0"
            or not re.search(r"(?:^|,)serial=qcl-bootstrap-root(?:,|$)", properties.get("virtio0", ""))):
        raise ValueError("Only the unprotected, tagged bootstrap VM with its exact root serial is owned")
    current = properties.get("args")
    if current and current != expected_args:
        raise ValueError("Existing QEMU arguments have another owner; do not overwrite or remove them")


if __name__ == "__main__":
    if len(sys.argv) != 3 or not re.fullmatch(r"[1-9][0-9]{2,8}", sys.argv[1]):
        raise SystemExit("Expected an explicit bootstrap VM ID and exact official kernel arguments")
    config = subprocess.check_output(["qm", "config", sys.argv[1]], text=True)
    validate_bootstrap(config, sys.argv[2])
