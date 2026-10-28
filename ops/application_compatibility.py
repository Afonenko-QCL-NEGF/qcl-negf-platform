"""Check installed internal requirements using native distribution metadata."""
from importlib.metadata import distribution

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def check_compatibility(names, *, get_distribution=distribution):
    selected = {canonicalize_name(name): get_distribution(name) for name in names}
    for owner, package in selected.items():
        for raw in package.requires or ():
            requirement = Requirement(raw)
            target = canonicalize_name(requirement.name)
            if target not in selected or (
                requirement.marker is not None and not requirement.marker.evaluate({"extra": ""})
            ):
                continue
            if selected[target].version not in requirement.specifier:
                raise ValueError(owner + " requires " + raw + "; installed " + selected[target].version)
    return {name: package.version for name, package in selected.items()}


if __name__ == "__main__":
    check_compatibility(("qcl-negf-contracts", "qcl-negf-results", "aiida-qcl-negf", "qcl-negf-api"))
