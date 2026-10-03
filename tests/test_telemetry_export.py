"""Small NDJSON-to-Parquet example; not a Vector ingestion/infrastructure test."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

try:
    import pyarrow.parquet as parquet
except ImportError:
    parquet = None

SPEC = importlib.util.spec_from_file_location(
    "telemetry_export", Path(__file__).parents[1] / "ops" / "telemetry_export.py"
)


def event(sequence):
    return {"schema": "qcl-runtime-event-v1", "event": "checkpoint", "name": "publish",
            "status": "observed", "attributes": {"attempt": 2, "bytes": 1024},
            "timestamp_unix_seconds": 123.5, "sequence": sequence}


@unittest.skipIf(parquet is None, "optional PyArrow export dependency is not installed")
class TelemetryExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ops = importlib.util.module_from_spec(SPEC)
        SPEC.loader.exec_module(cls.ops)

    def test_multiple_streaming_batches_preserve_events_without_changing_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "events.ndjson", root / "events.parquet"
            raw = "".join(json.dumps(event(i)) + "\n" for i in range(1, 6))
            source.write_text(raw)
            count = self.ops.export(source, target, batch_events=2)
            self.assertEqual(count, 5)
            self.assertEqual(source.read_text(), raw)
            records = parquet.read_table(target).to_pylist()
            self.assertEqual([json.loads(row["event_json"])["sequence"] for row in records], [1, 2, 3, 4, 5])

    def test_oversized_event_fails_before_publishing_parquet(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "events.ndjson", root / "events.parquet"
            source.write_text(json.dumps(event(1)) + "\n")
            with self.assertRaisesRegex(ValueError, "event.*budget"):
                self.ops.export(source, target, max_event_bytes=32)
            self.assertFalse(target.exists())
            self.assertEqual(list(root.iterdir()), [source])

    def test_output_byte_budget_fails_without_partial_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "events.ndjson", root / "events.parquet"
            source.write_text(json.dumps(event(1)) + "\n")
            with self.assertRaisesRegex(ValueError, "export.*budget"):
                self.ops.export(source, target, max_output_bytes=1)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
