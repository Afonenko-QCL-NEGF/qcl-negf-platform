"""The installed application follows package requirements, not root version equality."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


def compatibility():
    source = Path(__file__).parents[1] / "ops/application_compatibility.py"
    assert source.exists(), "the owning package compatibility validator is missing"
    spec = importlib.util.spec_from_file_location("application_compatibility", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.check_compatibility


def distributions(contracts="0.3.1"):
    return {
        "qcl-negf-api": SimpleNamespace(version="0.4.0", requires=[
            "aiida-qcl-negf>=0.2,<0.4", "qcl-negf-results>=0.3,<0.5",
            "qcl-negf-contracts[validation]>=0.3,<0.4",
            'qcl-negf-contracts==99; extra == "test"',
        ]),
        "aiida-qcl-negf": SimpleNamespace(version="0.2.5", requires=[
            "qcl-negf-contracts>=0.3,<0.4",
        ]),
        "qcl-negf-results": SimpleNamespace(version="0.3.2", requires=[
            "qcl-negf-contracts>=0.3,<0.4",
        ]),
        "qcl-negf-contracts": SimpleNamespace(version=contracts, requires=[]),
    }


def test_compatible_independent_component_versions_are_admitted():
    rows = distributions()
    result = compatibility()(tuple(rows), get_distribution=rows.__getitem__)
    assert result == {"qcl-negf-api": "0.4.0", "aiida-qcl-negf": "0.2.5",
                      "qcl-negf-results": "0.3.2", "qcl-negf-contracts": "0.3.1"}


def test_incompatible_declared_internal_requirement_is_rejected():
    rows = distributions(contracts="0.4.0")
    with pytest.raises(ValueError, match="qcl-negf-contracts"):
        compatibility()(tuple(rows), get_distribution=rows.__getitem__)


def test_normalized_distribution_names_do_not_bypass_requirements():
    rows = distributions(contracts="0.4.0")
    rows["qcl-negf-api"].requires = ["qcl_negf_contracts<0.4"]
    with pytest.raises(ValueError, match="qcl_negf_contracts"):
        compatibility()(tuple(rows), get_distribution=rows.__getitem__)


def test_native_distribution_metadata_accepts_independent_versions(tmp_path, monkeypatch):
    rows = distributions()
    for name, package in rows.items():
        metadata = tmp_path / (name.replace("-", "_") + "-" + package.version + ".dist-info")
        metadata.mkdir()
        metadata.joinpath("METADATA").write_text("Metadata-Version: 2.3\nName: " + name
            + "\nVersion: " + package.version + "\n"
            + "".join("Requires-Dist: " + requirement + "\n" for requirement in package.requires))
    monkeypatch.syspath_prepend(str(tmp_path))
    assert compatibility()(tuple(rows))["qcl-negf-api"] == "0.4.0"
