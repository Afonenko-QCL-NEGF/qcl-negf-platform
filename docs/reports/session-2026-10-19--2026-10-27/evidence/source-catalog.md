# Каталог первичных источников

[Общий отчёт](../README.md) · [Метод](README.md)

SHA256 ниже относится к исходному артефакту, **не** к отредактированной Markdown-проекции. Raw
receipts остаются у оператора: наличие hash без raw bytes не делает их публично воспроизводимыми.
Абсолютные пути, physical inventory, secrets и scientific arrays исключены.

| Evidence ID / operation                   | SHA256 оригинала                                                 | Доступность / граница                                                                     |
| ----------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| CP70                                      | eba940738fdaceaf34366ca05aa85597e003d4f982a88856b1676b41c5b44600 | Приватный полный coordination checkpoint; опубликована выборочная проекция                |
| JOURNAL-ARCHIVE                           | e61b01d842ae5d5d6ed89c0635cd33b63753bd59edda0e31ceba3bdb2dda75a9 | Приватный архив первых862operation records; это не SSH-prefix                             |
| QCL-SCI6-R5-HEALTH-PROGRESS-READ26        | f366b25ca641f48309fad57d982f4489dcc95f6ccf59a17edd694ba9a3617d03 | Приватный первичный receipt; доступны operation ID и SHA256, безопасная проекция в отчёте |
| QCL-SCI6-R5-MEMORY-BREAKDOWN-READ1        | ecc912b0495db4c18bc73930c774ac41878e7a1a9fdbb28e103e293060106805 | Приватный первичный receipt; доступны operation ID и SHA256, безопасная проекция в отчёте |
| QCL-SCI6-R5-MEMORY-BREAKDOWN-READ2        | 71b94d7d8636b460bdd955a28a251b3a46051ec045d2b226c92b69c388bdfa07 | Приватный первичный receipt; доступны operation ID и SHA256, безопасная проекция в отчёте |
| QCL-SCI6-R5-MEMORY-HISTORY-METADATA-READ1 | ce37f76a10eba5ff4d14f4e36ecedfc323a63ea65166a0d942d782c8dd93cec8 | Приватный первичный receipt; доступны operation ID и SHA256, безопасная проекция в отчёте |
| QCL-GUI-APP-REALIZATION2                  | a3b1cf66c86a947c039188c2e18a240494bc87fdbfb0a7180919f1a4473377d0 | Приватный первичный receipt; доступны operation ID и SHA256, безопасная проекция в отчёте |
| QCL-GUI-APP-NATIVE-READINESS8             | 9efa4aff077b5bc3a3eb157d3001b89b135b10cf4a302ce5bfdb0dd62efc69cf | Приватный первичный receipt; доступны operation ID и SHA256, безопасная проекция в отчёте |
| QCL-DOC04-RESOURCE-HOST-READ1             | a15aa8b02b38bb2652334b7d58d404686decf6bf8ab3f82fea57ce3c297c4b1f | Приватный первичный receipt; доступны operation ID и SHA256, безопасная проекция в отчёте |
| QCL-DOC04-CAPACITY-AND-PREPARED-READ3     | 208676da2c89c2eb537162109e15d109886865bdd06680d845975ac16d465a98 | Приватный первичный receipt; доступны operation ID и SHA256, безопасная проекция в отчёте |

## Публичные Git-источники

| Источник                        | Публичный locator                                                                                                                        | Роль и ограничение                                                    |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Handoff                         | [qcl-negf@e0f244d075dd](https://github.com/Afonenko-QCL-NEGF/qcl-negf/commit/e0f244d075dd49874ba4f3847f4efa693f3b3622)                   | Исходный пользовательский PR22, EXEC активирован сообщением оператора |
| Original preserved checkout     | [qcl-negf@e48e5b2ef16d](https://github.com/Afonenko-QCL-NEGF/qcl-negf/commit/e48e5b2ef16d3e6f1d633dd29c95f94d60ca8cc1)                   | Старый dirty checkout сохранён, не runtime науки                      |
| Operational checkpoint checkout | [qcl-negf@e5fc3069d712](https://github.com/Afonenko-QCL-NEGF/qcl-negf/commit/e5fc3069d7120925bb3e2df2b39a89c4f2360394)                   | Worktree с локальным checkpoint, не latest опубликованной integration |
| Scientific runtime              | [qcl-negf@cb1bae7ffdbb](https://github.com/Afonenko-QCL-NEGF/qcl-negf/commit/cb1bae7ffdbb977f33d81e05b8ebd50afb4177ee)                   | Источник runningSCI6; не текущий GUI candidate                        |
| GUI/docs candidate              | [qcl-negf@d395044ac09b](https://github.com/Afonenko-QCL-NEGF/qcl-negf/commit/d395044ac09b28c2ff573724f8911d625df43bf5)                   | RootPR35 draft, не deploy/fullCI                                      |
| Platform report base            | [qcl-negf-platform@1b1370d2b8e8](https://github.com/Afonenko-QCL-NEGF/qcl-negf-platform/commit/1b1370d2b8e83a267a97c8d49df14db220123478) | Integration base послеPR31; defaultmain0970338 исторический           |
| Core source audit               | [QCLNEGF.jl@5b1cdd458eb0](https://github.com/Afonenko-QCL-NEGF/QCLNEGF.jl/commit/5b1cdd458eb07ff8c7c792642eda58d9061e1017)               | Точный runtime Core, текстовый аудит                                  |
| Runner source audit             | [QCLNEGFRunner.jl@4609c2e0837d](https://github.com/Afonenko-QCL-NEGF/QCLNEGFRunner.jl/commit/4609c2e0837df92a831a265f006bc3262b1ae875)   | Точный runtime Runner, текстовый аудит                                |

Это исторические identities данного отчёта, не второй maintained revision lock. Источником состава
каждого root остаются его Git gitlinks. В CP top-level source.root_head=0071a985… сохранено
историческое значение; оно не представлено как текущая revision. Публичные PR refs и новые merge
подтверждены индексомPR.

## Независимые авторские аудиты

| Публикуемая проекция                                 | SHA256 исходного авторского audit                                | Граница                                                                            |
| ---------------------------------------------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| [cost-audit.md](cost-audit.md)                       | eba12e85a3a726badea3647d4aa2179e9b74fe1036b2acec7952f1dd4d232a18 | Приватные пути/физическая identity скрыты; исходный audit отдельно от raw receipts |
| [memory-source-audit.md](memory-source-audit.md)     | fc0bb248e00d69c142130c3e96c77cef0d9ab195e18f1313b5ac3295bc317063 | Приватные пути/физическая identity скрыты; исходный audit отдельно от raw receipts |
| [memory-runtime-review.md](memory-runtime-review.md) | e45acbcf2eb1cc5f7ec4570f789e361c10b601f11ce483e883279fdd2cd93472 | Приватные пути/физическая identity скрыты; исходный audit отдельно от raw receipts |
