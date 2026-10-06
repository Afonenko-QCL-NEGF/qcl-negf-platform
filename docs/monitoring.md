# Best-effort CPU monitoring

`qclNegf.monitoring.nodeExporter` enables the standard Prometheus node exporter;
only the private interface opens port 9100. Use an existing Prometheus/Grafana
installation to scrape it. Collector and exporter options default to disabled.

On one permanent node, `qclNegf.monitoring.collector.enable = true` selects
[Vector's HTTP JSON source](https://vector.dev/docs/reference/configuration/sources/http_server/)
at `/events`; set its address to the trusted LAN address deliberately (default
loopback). There are no authentication secrets in this example. Keep plaintext
HTTP within the trusted LAN or place a reviewed TLS proxy in front. The source
uses newline framing with 16 KiB per event. The file sink uses an in-memory
256-event buffer with `drop_newest` and disabled delivery acknowledgment; no WAL
or durable telemetry queue is introduced. The service is capped at 512 MiB/1 CPU.
Retention removes old NDJSON files after seven days by default. Retention is
not a physical disk reservation or a hard aggregate daily byte quota: provision
a measured volume and monitor free disk; telemetry may be lost on disk failure.

Events use the existing contracts `qcl-runtime-event-v1` schema. The Runner's
bounded asynchronous scalar-only sender owns transport/drop behavior; solver
never waits for HTTP, disk or acknowledgments. Scientific history/checkpoints,
stop receipts and scientific status remain independently durable.

A minimal installed-collector acceptance example is:

```console
printf '%s\n' '{"schema":"qcl-runtime-event-v1","event":"checkpoint","name":"publish","status":"observed","attributes":{"attempt":1,"bytes":1024},"timestamp_unix_seconds":123.5,"sequence":1}' | curl --fail -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8081/events
qcl-negf-telemetry-export /var/lib/vector/qcl-telemetry/events-YYYY-MM-DD.ndjson /private/new-export.parquet --max-output-bytes 10485760
```

The exporter reads bounded lines and 256-event batches with PyArrow, retains
canonical event JSON alongside searchable scalar columns and publishes only a
complete Parquet file. It leaves the source unchanged, refuses an existing
destination and enforces event/output byte budgets. It is offline postprocessing,
not part of checkpoint acknowledgment.

The local fixture verifies NDJSON → Parquet preservation across several batches
and refuses oversize/partial output. **Vector ingestion/export, runtime resource
overhead and Prometheus/Grafana integration are not_verified** because no server
or installed Vector executable was available. Nix evaluation only checks merged
configuration; building the image later runs Vector's upstream configuration
validator. Do not report the fixture as collector acceptance.

Keep `OPENBLAS_NUM_THREADS=1`, `OMP_NUM_THREADS=1`, `MKL_NUM_THREADS=1` and size
Julia threads from the one-node Slurm allocation. Measure safe iteration,
checkpoint bytes/write/publish time, scratch/recovery/archive peak storage, CPU
utilization, RSS and sender overhead on a fresh small run before tuning. More
requested CPUs alone is not evidence of faster solver execution.

The fictional [manual access inventory](../examples/access-inventory.md.example)
has no real secrets and is not a delivery input. Store the actual host/VM/user,
connection/key/password location and sudo/admin details in the protected private
site; no account synchronization or CMDB is provided.
