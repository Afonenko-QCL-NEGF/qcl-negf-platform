# Короткие проекции native gates

[Общий отчёт](../README.md) · [Hash-каталог](source-catalog.md)

Это численные поля из сохранённых receipts, а не команды для исполнения и не полные raw bytes. Их
hashes опубликованы в каталоге. `native8` проверяет только actor metadata read; строка exit0
отдельно от содержимого приведена намеренно. Engineering APP не активирован как service release и не
имеет full CI/browser acceptance. DOC04 probe не запускает candidate; selected guard false.
`MemTotal_minus_max_allocations` — арифметический остаток распределений, **не** гарантированная
физически свободная память. Два observations разного времени не являются атомарным ресурсным
snapshot.

```json
{
  "APP": {
    "state": "APP_REALIZED_AND_FRONTEND_BYTES_VERIFIED",
    "wall_seconds": 47.16576230099599,
    "memory.peak": "983105536\n",
    "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n",
    "build_calls": 1
  },
  "native8": {
    "unit_exit": 0,
    "failure": null,
    "nested_state": "INSTALLED_APP_ACTOR_READ_ONLY_METADATA_OBSERVED",
    "nested_error": null
  },
  "DOC04": {
    "memory": {
      "MemAvailable": 2963386368,
      "MemTotal": 4105854976,
      "SwapFree": 0,
      "SwapTotal": 0
    },
    "guard": {
      "DOC04_candidate_dispatches_this_packet": 0,
      "guest_reserve_bytes": 1073741824,
      "memory_cap_bytes": 3221225472,
      "passed": false,
      "required_MemAvailable_bytes": 4294967296
    },
    "prepared_forest_rows": 9,
    "all_clean": true,
    "input_sha_records": {
      "asset_inputs": {
        "bytes": 10884,
        "sha256": "b0f0ff4697a471ee9952b89acab835fb04a3f7d8dd8b0acb1a5329ded436ed3a"
      },
      "assets_lock": {
        "bytes": 109281,
        "sha256": "e9df72654344de646b57a3f358d75fbcd1bfe577c8f7f8182f197a69e3f6f103"
      },
      "manifest": {
        "bytes": 25261,
        "sha256": "a6cb226a2d6fe990e9a067658c16b44acdbaf984e68c3474232a22f72d8d8b47"
      },
      "plan": {
        "bytes": 2196,
        "sha256": "0c831c99453a7ae652662df0e92b2e9d2dbb9f804041891d47d6205dd2e32e65"
      },
      "project": {
        "bytes": 659,
        "sha256": "859c6e7b2aedf4b58cd48731ea9a3970d70a43e018796472ec99550d186fdafe"
      },
      "review_inputs": {
        "bytes": 41068,
        "sha256": "ccfa4ed7c80b02bfc4b6d20f9f66e133dba9c86fffaa78068547701c343e36ed"
      },
      "source_graph": {
        "bytes": 1654,
        "sha256": "eac21b49b068b7c391c00cf18111b6e23c5e5d7a506f088f4cd85ea2cd1a22fb"
      }
    },
    "candidate_dispatches_this_read": 0
  },
  "host": {
    "observed_Mem": {
      "MemAvailable": 9877090304,
      "MemTotal": 67011194880
    },
    "max_running_allocations_bytes": 62277025792,
    "MemTotal_minus_max_allocations": 4734169088,
    "above_4GiB_arithmetic_bytes": 439201792
  }
}
```

## Worker source kit

Сохранённый исходный Linux worker kit: 167383B, 37ZIPentries, 34trackedfiles, SHA256
`b2e074afa649525bb0eccd904cb086628affbf9336a59e32a04193beb9cdf664`. Исторический root543f49e указан
в его metadata, owning Platform1b137 совпадает с выбранной поздней GUI веткой; metadata не
переименованы в новый root. Это source/instruction kit, не QCOW, не подписанный bootable image и не
enrolled worker. Публичный guide находится в выбранном Platform source:
[linux-workers.md](https://github.com/Afonenko-QCL-NEGF/qcl-negf-platform/blob/1b1370d2b8e83a267a97c8d49df14db220123478/docs/linux-workers.md).

## Границы приёмки

Source review → engineering build → native metadata read → release update → authenticated
browser/docs/worker acceptance → final CI/science — разные свидетельства. Последовательность
зависимостей конкретных gates описана в основных разделах; перечисление здесь не задаёт новый
порядок pipeline. Успех раннего уровня не заменяет отсутствующие поздние результаты.
