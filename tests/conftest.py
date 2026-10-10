"""Explicit declared Ansible dependency checks for the three recording suites."""
import json
import os
from pathlib import Path
import sys

import pytest

_SHELL = "Use nix develop --no-update-lock-file --command deno task test:state"


def _assert_declared_ansible_origins(observed, expected):
    """Pure conjunction: matching versions never substitute for exact origins."""
    predicates = {
        "python_version": observed["python_version"] == (3, 14),
        "declared_engine_version": expected["engine_version"] == "2.21.1",
        "engine_version": observed["engine_version"] == expected["engine_version"],
        "launcher": observed["executable"] in (expected["launcher"], expected["base"]),
        "process_base": observed["process_executable"] == expected["base"],
        "engine_init": observed["engine_init"] == expected["engine_init"],
        "engine_release": observed["engine_release"] == expected["engine_release"],
        "no_user_site": observed["no_user_site"] == 1,
    }
    failed = [name for name, passed in predicates.items() if not passed]
    if failed:
        raise ValueError("Declared Ansible origin mismatch: " + ", ".join(failed))
    return predicates


def _declared_path(name, *, directory=False):
    value = os.environ.get(name, "")
    if not value or not Path(value).is_absolute():
        raise ValueError(name + " must be an explicit absolute path")
    path = Path(value).resolve(strict=True)
    if not (path.is_dir() if directory else path.is_file()):
        raise ValueError(name + " has the wrong file type")
    return path


def _manifest(directory, name, version, dependencies):
    info = json.loads((directory / "MANIFEST.json").read_text())["collection_info"]
    if (info["namespace"], info["name"], info["version"], info["dependencies"]) != (
        "community", name, version, dependencies
    ):
        raise ValueError("Unexpected collection manifest: " + str(directory))
    if not (directory / "FILES.json").is_file():
        raise ValueError("Missing upstream FILES.json: " + str(directory))


@pytest.fixture(scope="session")
def ansible_test_environment():
    """Validate declarations before imports, then inspect the effective resolver."""
    saved = {name: os.environ.get(name) for name in (
        "ANSIBLE_COLLECTIONS_PATH", "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH"
    )}
    try:
        root = _declared_path("QCL_TEST_ANSIBLE_COLLECTIONS", directory=True)
        base = _declared_path("QCL_TEST_PYTHON_BASE")
        launcher = _declared_path("QCL_TEST_PYTHON_LAUNCHER")
        output = _declared_path("QCL_TEST_ANSIBLE_ENGINE_OUTPUT", directory=True)
        # The suffix is declared by Nix, never inferred from an imported module.
        declared_root = Path(os.environ.get("QCL_TEST_ANSIBLE_ENGINE_ROOT", ""))
        declared_output = Path(os.environ["QCL_TEST_ANSIBLE_ENGINE_OUTPUT"])
        if not declared_root.is_absolute():
            raise ValueError("QCL_TEST_ANSIBLE_ENGINE_ROOT must be an explicit absolute path")
        suffix = declared_root.relative_to(declared_output)
        if suffix == Path(".") or ".." in suffix.parts:
            raise ValueError("Engine root must be a descendant of the declared output")
        engine_root = _declared_path("QCL_TEST_ANSIBLE_ENGINE_ROOT", directory=True)
        if engine_root != (output / suffix).resolve(strict=True) or not engine_root.is_relative_to(output):
            raise ValueError("Engine root escapes the declared output")
        expected = {
            "base": str(base), "launcher": str(launcher),
            "engine_init": str((engine_root / "__init__.py").resolve(strict=True)),
            "engine_release": str((engine_root / "release.py").resolve(strict=True)),
            "engine_version": os.environ.get("QCL_TEST_ANSIBLE_ENGINE_VERSION", ""),
        }
        # Reject foreign interpreter metadata before any Ansible import.
        executable = str(Path(sys.executable).resolve(strict=True))
        process_executable = str(Path("/proc/self/exe").resolve(strict=True))
        if sys.version_info[:2] != (3, 14) or executable not in (str(base), str(launcher)):
            raise ValueError("Current Python is outside the declared Python 3.14 routes")
        if process_executable != str(base) or sys.flags.no_user_site != 1:
            raise ValueError("Current process base/no-user-site differs from the declaration")
        if expected["engine_version"] != "2.21.1":
            raise ValueError("Missing or unsupported declared Ansible engine version")
        general = root / "ansible_collections/community/general"
        library = root / "ansible_collections/community/library_inventory_filtering_v1"
        _manifest(general, "general", "13.4.0", {"community.library_inventory_filtering_v1": ">=1.0.0"})
        _manifest(library, "library_inventory_filtering_v1", "1.1.5", {})
        import yaml
        requirements = yaml.safe_load((Path(__file__).resolve().parents[1] / "ansible/requirements.yml").read_text())
        if requirements["collections"] != [
            {"name": "community.general", "version": "13.4.0"},
            {"name": "community.library_inventory_filtering_v1", "version": "1.1.5"},
        ]:
            raise ValueError("Declared collections disagree with owning Ansible requirements")
        os.environ["ANSIBLE_COLLECTIONS_PATH"] = str(root)
        os.environ["ANSIBLE_COLLECTIONS_SCAN_SYS_PATH"] = "false"
        import ansible
        import ansible.release
        observed = {
            "python_version": sys.version_info[:2], "engine_version": ansible.release.__version__,
            "executable": executable, "process_executable": process_executable,
            "engine_init": str(Path(ansible.__file__).resolve(strict=True)),
            "engine_release": str(Path(ansible.release.__file__).resolve(strict=True)),
            "no_user_site": sys.flags.no_user_site,
        }
        predicates = _assert_declared_ansible_origins(observed, expected)
        from ansible.plugins.loader import init_plugin_loader, module_loader
        from ansible.utils.collection_loader import AnsibleCollectionConfig
        from ansible.utils.collection_loader._collection_finder import _get_collection_path
        if AnsibleCollectionConfig.collection_finder is None:
            init_plugin_loader([str(root)])
        resolved = {}
        for name in ("lvol", "filesystem"):
            context = module_loader.find_plugin_with_context("community.general." + name)
            wanted = (general / "plugins/modules" / (name + ".py")).resolve(strict=True)
            if not context.resolved or Path(context.plugin_resolved_path).resolve(strict=True) != wanted:
                raise ValueError("Foreign/unresolved community.general." + name)
            resolved[name] = str(wanted)
            _manifest(wanted.parents[2], "general", "13.4.0", {"community.library_inventory_filtering_v1": ">=1.0.0"})
        actual_library = Path(_get_collection_path("community.library_inventory_filtering_v1")).resolve(strict=True)
        if actual_library != library.resolve(strict=True):
            raise ValueError("Foreign inventory filtering library namespace")
        _manifest(actual_library, "library_inventory_filtering_v1", "1.1.5", {})
        yield {"expected": expected, "observed": observed, "predicates": predicates,
               "modules": resolved, "library": str(actual_library)}
    except (ValueError, OSError, KeyError, TypeError, ImportError) as error:
        pytest.fail(str(error) + ". " + _SHELL, pytrace=False)
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
