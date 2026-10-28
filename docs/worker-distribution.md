# Частный worker packet: локальные assemble и verify

[worker_distribution.py](../ops/worker_distribution.py) копирует уже подготовленные nonsecret
artifacts в новый каталог private engineering candidate и проверяет их. Он не собирает image, не
устанавливает пакеты, не исполняет recipes, не вызывает Nix, не обращается к сети и не меняет
controller, enrollment, admission или guest. Единственная инструкция install/update/rollback —
[Linux workers](linux-workers.md). Этот путь относится к Arch x86_64/libvirt/KVM. Proxmox и обе
Windows/Hyper-V машины, restore/fault gates, final source, sole final CI и scientific acceptance
остаются отдельными обязательными проверками.

Schema `qcl-negf-worker-distribution-v1` связывает original release/source/image, а не
переопределяет их. Никакого нового revision lock нет. Новый toolkit commit может отличаться от
payload graph; старый runtime/native receipt не становится приёмкой нового GUI release. Профиль
только `site_bound_private`, purpose только `private_engineering_candidate`. Public/reusable release
этим инструментом не объявляется.

## Входы publisher

Нужны actual positive byte counts, original release JSON и source graph, полный producer
`images.json` с четырьмя ролями и `arch-worker`, selected QCOW2, original Root
`flake.lock`/`uv.lock`/Julia `Manifest.toml`, existing depot metadata и проверенные build/content
evidence. Старый producer сохраняет path/SHA/bytes, но не полный build join: такой `images.json`
**недостаточен**. Missing source/derivation/NAR/content evidence останавливает actual сборку
каталога; текущий checkout не заменяет исторический receipt. Из исходных private receipts оператор
готовит bounded typed nonsecret projections, сохраняя SHA256 original receipt и само original
evidence у publisher. Это ручная передача свидетельств из существующих records, не дополнительный
build или тест.

Подготовьте отдельный input directory с **ровно** файлами из `files` предложенного manifest. Все
входы задаются explicit FileRefs `{path,bytes,sha256}` внутри manifest: normalized relative POSIX
paths, positive integer bytes, lowercase SHA256. Произвольные extra paths, duplicate refs, symlinks,
hardlinks, devices, FIFO и traversal запрещены. Исходный manifest хранится вне input directory.
Original metadata копируется без перезаписи. Secrets, private inventories/tfvars/state/known_hosts,
enrollment, private keys и live ready state не входят в bundle. Content evidence должно отдельно
подтверждать отсутствие secrets и унаследованной identity в самом image; filename filter не
считается проверкой отсутствия secrets.

Canonical payload:

```text
README.md
images/worker-root.qcow2
records/release.json
records/source-graph.json
records/images.json
records/image-build.json
records/image-content.json
records/depot.json
records/locks/flake.lock
records/locks/uv.lock
records/locks/Manifest.toml
recipes/platform/source-kit.json
recipes/platform/... public tracked installation source ...
```

Допустимы дополнительные original locks внутри `records/locks/`, optional
`records/native-reuse.json`, `records/image_first_boot.json`, `records/backend_install.json` только
при соответствующих refs. `worker-distribution.json` и `SHA256SUMS` создаёт assembler; они исключены
из payload `files` во избежание циклических hashes. README publisher содержит реальный
маршрут/medium, получателя, filenames/bytes, trusted expected manifest SHA, missing/measured matrix.
Неизвестный маршрут обозначают `blocked`; store path и documentation URL не становятся download
link.

## Manifest

Top-level keys ровно: `schema`, `purpose`, `profile`, `architecture`, `role`, `backend`,
`release_id`, `source_graph`, `release_manifest`, `image_manifest`, `image`, `runtime_evidence`,
`installation_kit`, `controller`, `host_requirements`, `acceptance`, `files`. Unknown keys,
duplicate JSON keys и nonfinite numbers отвергаются. `architecture=x86_64-linux`, `role=worker`,
`backend=arch-libvirt`. Manifest/каждый metadata/source file ≤1 MiB, source kit ≤64 MiB, payload
≤4096 files. QCOW2 читается потоково по 64 KiB, measured размер задаётся original producer record.

`source_graph`, `release_manifest`, `image_manifest` — FileRefs canonical records выше. Parsed graph
обязан точно совпасть с `release.sources`; original producer release ID сохраняется и не
пересчитывается другим JSON canonicalizer. Existing release validators проверяют APP/SOLVER paths и
два closure NAR hashes; assembler дополнительно проверяет все joins. Full four-role images map
сохраняется; выбирается только `arch-worker`.

`image` содержит ровно:

| Ключ                                               | Значение                                                     |
| -------------------------------------------------- | ------------------------------------------------------------ |
| `file`                                             | FileRef `images/worker-root.qcow2`                           |
| `producer_role` / `format`                         | `arch-worker` / `qcow2`                                      |
| `boot_mode` / `hyperv_generation`                  | `legacy-bios` / `null`                                       |
| `partition_table` / `root_filesystem` / `root_bus` | `legacy` / `ext4` / `virtio`                                 |
| `derivation` / `output` / `nar_hash`               | Actual immutable image `.drv`, output store path, SRI SHA256 |
| `build_evidence` / `content_evidence`              | FileRefs canonical projection records                        |

QCOW2 magic/version — только header check. Self-contained/no external backing/data file,
firmware/partition/bus, runtime closures, no secrets и inherited identities подтверждаются original
content inspection receipt, не header или label версии.

`runtime_evidence` имеет `lock_artifacts:[FileRef,...]`, `depot:FileRef`,
`native_reuse:FileRef|null`, `native_status:not_measured|verified_for_exact_contract`. Existing
`qcl-negf.julia-depot.v1` bytes сохраняются: `format,sources,julia,juliaManifest,
url,hash`; Julia
`1.13.0`, graph и original `Manifest.toml` hash должны совпасть. Archive URL сохраняется как
provenance; доступность/cold rebuild не проверяются.

`installation_kit` имеет exact published `platform_revision`, `files:[FileRef,...]`,
`guide=recipes/platform/docs/linux-workers.md`,
`template=recipes/platform/examples/private-site/flake.nix.template`,
`recipe=recipes/platform/tofu/arch-libvirt/main.tf`. Нужны Arch playbook/requirements, все provider
.tf files и example, verifier с его двумя local Python dependencies, и все local targets Markdown
links (проверяются рекурсивно среди shipped docs). `source-kit.json` имеет ровно
`schema=qcl-negf-worker-source-kit-v1`, `platform_revision`, `files` (ровно kit refs; сам receipt
исключён), `original_receipt_sha256`, `public_tracked_only=true`, `secrets_absent=true`. Последние
поля требуют исходного проверенного nonsecret published export receipt; filename filter или текущий
checkout не заменяют это свидетельство. Это trusted publisher export declaration о published source,
не самостоятельная Git/signature проверка. Private untracked config не включают. Payload locks
берутся из original payload graph, kit — из отдельного published Platform source.

`controller` имеет `release_schema=qcl-negf-release-v1`, exact `release_id`,
`enrollment="existing protected enrollment v1; provisioned separately"`,
`first_boot="DRAIN/no-submit before trust+release+health"`. `host_requirements` имеет ровно:

```json
{
  "host_adapter": "Arch Linux x86_64; measured versions required",
  "virtualization": "KVM",
  "network": "existing LAN bridge; no NAT",
  "libvirt_provider": "dmacvicar/libvirt=0.9.9",
  "opentofu": ">=1.10,<2.0",
  "scratch": "separate stable-identity disk; actual capacity/reserve required"
}
```

`acceptance.image_first_boot` и `.backend_install` имеют `status=not_measured,receipt=null` либо
`status=measured,receipt=FileRef`. Measured означает наличие exact observations, не автоматический
PASS. `final_source`, `final_ci`, `full_release` всегда `not_claimed`. Machine/target/resource
values из реального private install plan здесь не выдумываются.

## Typed projection receipts

Projection schemas ниже ограничивают передачу существующего evidence; они не создают новый producer
format или protocol registry. Дополнительные keys запрещены. Каждый projection несёт
`original_receipt_sha256` (64 lowercase hex). Original bytes/hash остаются у publisher, redaction не
улучшает исходный verdict. Trusted expected manifest SHA привязывает эти утверждения к handoff, но
не делает их подписью.

Общий `identity` ровно: `release_id`, `source_graph_sha256`, `release_manifest_sha256`,
`image_sha256`, `image_bytes`, `derivation`, `output`, `nar_hash`, `closures`. Все значения должны
совпасть с manifest/original records; `closures` — exact producer APP/SOLVER list с
`{path,narHash}`, включая порядок.

- Build: `schema=qcl-negf-worker-build-projection-v1`, `original_receipt_sha256`, `identity`,
  `depot_sha256`, `lock_artifacts:[FileRef,...]`, `julia_manifest_sha256`, `native_contract`.
  Locks/depot/Julia hash должны совпасть с original files.
- `native_contract`: `source_sha256` (graph artifact), `test_sha256`, `factory_sha256`, `profile`,
  `args:[string,...]`, `julia`, `blas`, `phases:[string,...]`, `imports:[string,...]`. Это полный
  original test contract, не только версия/derivation.
- Content: `schema=qcl-negf-worker-content-projection-v1`, `original_receipt_sha256`, `identity`,
  `format,boot_mode,partition_table,root_filesystem,root_bus` (как image), `external_backing=false`,
  `external_data_file=false`, `secret_bytes=false`, `machine_id=false`, `ssh_host_keys=false`,
  `enrollment=false`, `runtime_ready=false`, `runtime_closures_present=true`,
  `observations:[string,...]`. Отсутствующий inspection receipt не допускает выдачу recipient;
  данный narrow assembler требует его до copy.
- Optional native reuse: `schema=qcl-negf-worker-native-projection-v1`, `original_receipt_sha256`,
  `identity`, identical `native_contract`, `observations`,
  `measurements:{phases:[...],imports:[...]}`. Каждая measurement имеет ровно
  `name,status=passed,receipt_sha256`; names/order обязаны совпасть с contract. Changed
  source/test/factory/profile/args/Julia/BLAS/phases/imports запрещают reuse. Отсутствующий native
  receipt допускается только как `not_measured` candidate.
- Optional install/first-boot: `schema=qcl-negf-worker-install-projection-v1`,
  `original_receipt_sha256`, `identity`, `kind=image_first_boot|backend_install`, `target` (actual
  nonempty target), `observations:[string,...]`.

Никакой `pass:true` без matching identity и contract не принимается. Typed projections не заменяют
независимую проверку original facts перед их подготовкой. Literal tiny fixtures не являются
реальными inspection/native receipts.

## Локальные команды и I/O admission

После отдельного actual bytes/disk/time admission, из доверенного source:

```sh
python3 "$TRUSTED_PLATFORM/ops/worker_distribution.py" assemble \
  --manifest "$PROPOSED_MANIFEST" --source "$PREPARED_INPUT" --output "$NEW_OUTPUT" \
  --disk-budget-bytes "$ADMITTED_BYTES" --timeout-seconds "$ADMITTED_SECONDS"
python3 "$TRUSTED_PLATFORM/ops/worker_distribution.py" verify "$NEW_OUTPUT" \
  --expected-manifest-sha256 "$EXPECTED_MANIFEST_SHA256" \
  --timeout-seconds "$ADMITTED_VERIFY_SECONDS"
```

Timeouts — целые 1..3600 секунд, disk budget positive и включает все новые bytes, manifest/checksums
и ≥64 MiB reserve. Publisher отдельно учитывает resident source image/store/archives,
staging/recipient/root-overlay/scratch, I/O и inode reserve. Равный hash не уменьшает занимаемое
место. Image копируется один раз, затем читается после fsync для проверки size/SHA/header. Metadata
проверяется до copy и после неё. Verifier читает каждый файл; это отдельное полное чтение image с
конечным бюджетом.

Output резервируется exclusive, existing output не перезаписывается. Payload files, checksum list и
directories синхронизируются до atomic final manifest publication. Failure оставляет named output с
`.incomplete`/`.manifest.partial` для reconciliation, не advertised completed manifest; исходники
сохраняются. Не делайте blind retry поверх partial directory и не удаляйте чужие attempts.
`SHA256SUMS` — exact sorted ASCII lines для payload и manifest, bytes сравниваются внутри Python,
без запуска shell. Verifier требует independently supplied expected **manifest** SHA, exact file set
и все joins; recipes он не исполняет. Self-produced checksum — не trust root/signature.

Завершённая локальная проверка каталога не доказывает передачу получателю, наличие маршрута,
recipient readback, boot, enrollment, уникальность новых identities или scientific correctness.
Install использует existing prepare-initial/node-check и protected controller lifecycle согласно
canonical Linux guide; новой команды enroll нет.

## Depot v2: original producer и CURRENT build

`qcl-negf-worker-build-projection-v2` содержит прежние поля build projection и закрытый
`depot_compatibility` с schema `qcl-negf-worker-depot-binding-v1`, `producer_source_graph_sha256`,
`selected_source_graph_record_sha256`, `inputs_sha256`, `consumed_metadata_sha256`,
`consumed_metadata_bytes`. Его создаёт pure Root export `workerDepotBinding` из actual build result
и exact source-graph record.

Depot v2 сохраняет шесть original provenance fields и добавляет `compatibility`: закрытые `schema`,
`inputs`, `inputs_sha256`, `native`. Native summary связывает exact Julia factory drv/output,
observed platform и hashes preferences/selector closure/artifact selection/ qualification receipt.
Это assertion trusted producer, не новое native измерение verifier. V1 depot/build projection
сохраняют прежний closed exactgraph contract; cross-pair запрещён.

Для v2 `records/depot.json` содержит exact normalized consumed JSON bytes Root build, ≤65536 bytes.
FileRef hash/length совпадают с binding. Original raw captured input остаётся у publisher. Producer
graph digest — compact recursively sorted ASCII graph JSON; selected record checksum — реальные
bytes FileRef, они не смешиваются. Original depot graph может отличаться от CURRENT;
release/image/native-test/source record остаются CURRENT. Archive URL/SRI и Manifest/lock joins не
ослабляются. Proof metadata не добавляется в dependency/runtime derivation.

Native factory/selector/default qualification, offline package installCheck, transport, first boot и
backend install по-прежнему отдельные gates. Verifier не делает их PASS по checksum или exit code.
