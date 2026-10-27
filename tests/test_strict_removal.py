"""The retired capacity-proof entry point is unavailable to callers."""
import importlib.util
from pathlib import Path
import sys


def test_campaign_capacity_proof_cannot_be_imported():
    root = str(Path(__file__).resolve().parents[1])
    sys.path.insert(0, root)
    try:
        assert importlib.util.find_spec("ops.scientific_resource_admission") is None
    finally:
        sys.path.remove(root)
