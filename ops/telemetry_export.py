"""Bounded offline export of existing telemetry, separate from scientific data."""
import argparse
import json
import os
from pathlib import Path
import tempfile


def export(source, target, *, batch_events=256, max_event_bytes=16384,
           max_output_bytes=1073741824):
    import pyarrow as arrow
    import pyarrow.parquet as parquet

    if min(batch_events, max_event_bytes, max_output_bytes) < 1:
        raise ValueError("Use positive telemetry export budgets")
    source, target = Path(source), Path(target)
    if target.exists() or source.resolve() == target.resolve():
        raise ValueError("Telemetry export must use a new destination")
    schema = arrow.schema([
        ("event", arrow.string()), ("name", arrow.string()), ("status", arrow.string()),
        ("timestamp_unix_seconds", arrow.float64()), ("sequence", arrow.int64()),
        ("event_json", arrow.string()),
    ])
    count = 0
    with tempfile.NamedTemporaryFile(dir=target.parent, delete=False) as handle:
        temporary = Path(handle.name)
    try:
        with source.open("rb") as stream, parquet.ParquetWriter(temporary, schema) as writer:
            rows = []
            while True:
                raw = stream.readline(max_event_bytes + 1)
                if not raw:
                    break
                if len(raw) > max_event_bytes:
                    raise ValueError("Telemetry event exceeds its byte budget")
                value = json.loads(raw)
                if value.get("schema") != "qcl-runtime-event-v1":
                    raise ValueError("Expected the contracts runtime-event schema")
                rows.append({"event": value["event"], "name": value["name"], "status": value["status"],
                             "timestamp_unix_seconds": value["timestamp_unix_seconds"],
                             "sequence": value.get("sequence"),
                             "event_json": json.dumps(value, sort_keys=True, allow_nan=False)})
                count += 1
                if len(rows) == batch_events:
                    writer.write_table(arrow.Table.from_pylist(rows, schema=schema))
                    rows.clear()
                    if temporary.stat().st_size > max_output_bytes:
                        raise ValueError("Telemetry export exceeds its byte budget")
            if rows:
                writer.write_table(arrow.Table.from_pylist(rows, schema=schema))
        if temporary.stat().st_size > max_output_bytes:
            raise ValueError("Telemetry export exceeds its byte budget")
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        return count
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path)
    parser.add_argument("--batch-events", type=int, default=256)
    parser.add_argument("--max-event-bytes", type=int, default=16384)
    parser.add_argument("--max-output-bytes", type=int, default=1073741824)
    args = parser.parse_args()
    print(json.dumps({"events": export(args.source, args.target, batch_events=args.batch_events,
                                       max_event_bytes=args.max_event_bytes,
                                       max_output_bytes=args.max_output_bytes)}))
