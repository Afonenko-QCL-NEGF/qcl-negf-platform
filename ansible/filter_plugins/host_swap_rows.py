"""Owning pure swap-table adapter; no native actions or fallback parsing."""
import importlib.util
from pathlib import Path
_source=Path(__file__).resolve().parents[2]/"ops/host_swap_file_probe.py"
_spec=importlib.util.spec_from_file_location("qcl_host_swap_file_probe",_source)
_probe=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_probe)
class FilterModule:
    def filters(self):
        return {"qcl_swapon_raw":_probe.normalize_swapon_raw}
