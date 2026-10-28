# Состав приложения

Superproject `qcl-negf` выбирает ревизии компонентов через Git submodules в `components/`.
Python workspace читает зависимости из четырёх package `pyproject.toml` и фиксирует внешнюю
среду в одном generated `uv.lock`. Используется Python 3.14; выбранные Nixpkgs и development
interpreter предоставляют 3.14.7.

| Владелец | Авторитетный вход |
| --- | --- |
| Git tree superproject | Точные ревизии исходников компонентов |
| Python packages | Runtime dependencies, extras, test groups и build backends |
| Superproject `uv.lock` | Разрешённые версии внешних Python packages и hashes артефактов |
| Platform `flake.lock` | Nixpkgs, uv2nix и инструменты сборки |
| Portal `package-lock.json` | Граф зависимостей браузерного приложения |
| Julia projects | Численные зависимости и generated manifests |

Platform не копирует Python dependency lists и внутренние source revisions в дополнительный
manifest. Infrastructure modules можно оценивать независимо от дерева исходников приложения.

## Разработка и обновление зависимостей

Из корня superproject:

```console
git submodule update --init --recursive
uv sync --locked --all-packages --all-extras --group test --group build
```

Измените native metadata командой `uv add --package PACKAGE DEPENDENCY` или отредактируйте
`pyproject.toml`, затем выполните `uv lock`. Для намеренного обновления внешних зависимостей
используйте `uv lock --upgrade` или `uv lock --upgrade-package NAME`. Запустите тесты и
зафиксируйте generated lock вместе с нужными submodule updates. Копировать внутренние commit
hashes в CI configuration не требуется.

Общая среда служит для integration. Отдельно распространяемые пакеты сохраняют обычные
версионированные зависимости и устанавливаются из wheels или package index. Root CI может
передавать неопубликованные внутренние wheels через wheelhouse; Results не зависит от AiiDA
или Portal.

## Native Nix сборка

Flake superproject передаёт полное дерево исходников:

```nix
platform.lib.mkApplication {
  system = "x86_64-linux";
  workspaceRoot = self.outPath;
}
```

`mkApplication` возвращает обычную uv2nix virtual environment с Contracts, Results, AiiDA plugin
и API. uv2nix читает native workspace и lock, собирает local packages через выбранный Hatchling
backend и устанавливает standard distribution metadata и entry points. Owning Nix recipe
Portal собирает browser assets и включает их в API wheel. Ручная распаковка wheels и runtime
сборка `PYTHONPATH` не нужны.

Сборка проверяет совместимость установленных внутренних пакетов по их native distribution requirements, markers и версиям; равенство версий всех компонентов версии root не требуется. Проверяются entry points AiiDA calculation, parser и workflow. `lib.mkPythonEnvironment` принимает те же `system` и `workspaceRoot`, а `includeTests = true` добавляет development groups и extras. Production environment содержит runtime dependencies.

Передайте результат как `qclNegf.application.package`; API включается отдельно через
`qclNegf.application.api.enable = true`. Изменяемое состояние AiiDA, credentials и данные
расчётов находятся вне immutable package. Private site configuration задаёт service token
и разрешённые Code UUIDs.

### Bootstrap локального профиля и TLS

Автоматический bootstrap использует Python объявленного application profile до того, как
`verdi run` загрузит database environment. `ops/bootstrap_profile.py` проверяет стандартные
storage fields `core.psql_dos` и передаёт поддерживаемые `engine_kwargs.connect_args` для
`/run/postgresql`, database `qcl-negf`, port 5432. Объявленный hostname не меняется; PostgreSQL
сохраняет peer authentication без TCP. Один profile CLI не сохраняет это runtime field.

Для нового профиля bootstrap проверяет peer identity и пустую database в read-only transaction
и требует отсутствующий либо полностью пустой repository. Затем вызывается public storage
lifecycle с `reset=False`, сохраняется Profile и создаётся default user. AiiDA может очистить
частично созданный контейнер даже с `reset=False`, поэтому bootstrap отказывается работать
с partial/nonempty repositories. Такое состояние проверяют и сохраняют отдельно. Для
совпадающего существующего профиля добавляются только отсутствующие socket connection
settings с сохранением UUID, прочих engine options и provenance; конфликт блокирует действие.
Далее применяется существующее reconciliation Computer и immutable InstalledCode.

Local Slurm Computer объявляет `#!/run/current-system/sw/bin/bash` для batch scripts; базовый
модуль устанавливает Bash на каждый QCL node. У NixOS нет переносимого контракта `/bin/bash`.
Reconciliation проверяет сохранённый shebang, transport, scheduler и work directory и
отказывается менять legacy/conflicting Computer, его UUID, Code и provenance. На существующей
установке сначала сохраните identity/history и проверьте executable interpreter на worker,
затем намеренно мигрируйте Computer через публичный AiiDA метод
`Computer.set_shebang("#!/run/current-system/sw/bin/bash")`. Это отдельное действие оператора.
Local render `get_submit_script` проверяет первую строку без отправки задания.

Опциональный общий proxy заменяет site-local nginx boilerplate:

```nix
qclNegf.application.api.tls = {
  enable = true;
  # Runtime files от site secret service вне store.
  certificateFile = "/run/secrets/qcl-negf-tls.crt";
  keyFile = "/run/secrets/qcl-negf-tls.key";
  serverName = "localhost";
};
```

Proxy слушает только `127.0.0.1:443` (TLS port настраивается), использует `onlySSL = true`
и передаёт запросы существующему loopback API port. systemd `LoadCredential` предоставляет
nginx читаемые private copies после объявленных `qclNegf.runtimeSecretUnits`. Private site
задаёт certificate identity, keys и внешний access tunnel. При включении удалите дублирующий
API virtual host из site configuration. TLS включается явно.

## Wheels и доставка

После однократной подготовки image [application CD](application-cd.md) обновляет стабильный
profile/runtime configuration без пересборки OS и сохраняет immutable solver Code identities.
Обычная доставка использует существующий общий GitHub Actions workflow.

Перед сборкой распространяемых Python wheels соберите browser assets:

```console
npm --prefix components/qcl-negf-portal/frontend ci
npm --prefix components/qcl-negf-portal/frontend run build
uv build --all-packages --no-build-isolation --no-sources
nix build .#application
```

Dependency group `build` предоставляет build backends из общего lock для Python build
command. Nix build использует тот же root workspace и выбранные Nix build tools. Generated
wheels и Nix closures хранятся в CI artifact storage или binary cache вне source history.

Julia — отдельная численная среда, которой владеют `QCLNEGF.jl` и runtime adapter
`QCLNEGFRunner.jl`. Изменение API или Results view не требует пересборки Julia dependency
environment. На submission и execution nodes устанавливается одна solver closure.

## Опциональный bounded preview конфигурации

Существующий API unit может включить bounded Runner `configure` для каталога и preview:

```nix
qclNegf.application.api.configurator.enable = true;
```

По умолчанию функция выключена. Дополнительный scheduler, сервис-планировщик и sudo grant
не создаются. Runner владеет parsing и scientific resolution; preview не отправляет расчёт и
не доказывает сходимость или научную приёмку.

Активный APP содержит `share/qcl-negf/runtime.json` со схемой
`qcl-negf-application-runtime-v1` и `configurator.catalog_root`: точным immutable Research root.
Источник Research выбирается из `sources.components` защищённого
`/var/lib/qcl-negf-admin/runtime/release.json`. Старые опции `catalogRoot` и `catalogSourceId`
удалены: при миграции их следует убрать из site configuration. Git graph остаётся источником
ревизий; descriptor не создаёт второй lock.

[Runtime helper](../ops/runtime_bindings.py) читает root-owned record, разрешает оба активных
application/solver profile и проверяет их точное соответствие record. Descriptor читается из
выбранной immutable APP closure, а не из package, записанного при сборке NixOS. Неизменные
solver/catalog и сохранённые Results продолжают работать после совместимого APP update без
пересборки OS. Отсутствующая metadata, неизвестная схема, неверный profile, solver или catalog
оставляют configurator недоступным с причиной в journal; базовый API запускается.

Проверки namespace запрещают traversal, symlink, чужого владельца и writable metadata. Только
сам `/nix/store` может иметь native sticky group-write mode; его выбранный entry и все
последующие directories/files должны быть root-owned и недоступны для записи группе/прочим.
Это проверка доверенного пути. Artifact integrity/qualification остаётся отдельным gate.

Helper удаляет унаследованные `QCL_NEGF_CONFIGURATOR_*`, `QCL_NEGF_QUANTUM_RUNTIME_*` и
`QCL_NEGF_SAVED_RESULTS_BINDING_FILE`, затем формирует явный child environment и вызывает API
через `execve` с argv. Parent и вложенный `verdi` используют одну выбранную immutable APP.
Shell `source`, `eval`, разбор строк с export и пользовательский исполняемый путь не нужны.
Authoritative `allowedCodesFile` читается как regular nofollow file с пределом 4096 bytes;
пустой или oversized файл блокирует запуск API и не заменяется унаследованным allowlist.

Read-only configuration и Results не приобретают job-admission gate. Startup может читать
явный `ready:false`, поскольку activation сначала запускает API, а затем проверяет health.
`runtime_bindings(..., require_ready=True)` требует текущую готовность; существующий Portal
quantum request повторно проверяет `ready:true`, exact protected record и profiles на каждый
запрос. Переход `false → true` не требует перезапуска API. Job guard и artifact qualification
остаются у release owner; startup не устанавливает scientific acceptance.

Unit сохраняет non-root пользователя, NoNewPrivileges, ProtectSystem, существующие writable
paths, authentication и nginx. Включение configurator добавляет `Delegate=cpu memory pids`,
`DelegateSubgroup=api`, `KillMode=control-group`; cgroup root выводится из реального Slice.
Runner adapter проверяет unified v2/controllers/permissions, делает cap readback и владеет
очисткой child group. Nix wiring само по себе не доказывает runtime readiness.

Проверки mount используют общий owning `application_release.command`: literal argv, timeout,
combined output bound и подтверждённую очистку своей process group. При ошибке сохраняется
исходный bounded `CommandFailure.record` в mode-0600 JSON под
`/var/lib/qcl-negf/runtime-failures`; native tmpfiles очищает старые файлы через 7 дней.
В journal остаются причина и ссылка. Ошибка сохранения лога не заменяет original command
failure успехом. Аргументы и environment не записываются в этот лог.

Перед включением на установленном узле отдельно проверяют module evaluation, root-owned
namespace, delegated cgroup/Runner readiness и advertised source identity. Source fixtures не
доказывают installed service, NFS, boot или научный результат. Offline/no-URI contract Runner
также не является network sandbox.

## Опциональное отображение сохранённых NFS Results (L1)

`qclNegf.application.api.savedResults.enable` по умолчанию выключен. L1 предоставляет
зарегистрированные закрытые Results из существующего NFS mount
`qclNegf.cluster.jobDirectory` существующему API unit через `/run/qcl-negf-saved`. Произвольный
request path/root не принимается. Producer сохраняет hard NFSv4 mount и daemon write access.
API получает `RequiresMountsFor` для mount и site identity file, `BindReadOnlyPaths` для alias
и `ReadOnlyPaths` для original path/identity file. Writable state paths не меняются.
Отсутствующий обязательный source не является optional bind: префикс `-` недопустим.

Включайте функцию только после private site admission со всеми параметрами:

- `namespaceId`: 1–128 символов; первый буквенно-цифровой, далее также допустимы точка,
  underscore и hyphen. Namespace нельзя повторно использовать для другой disk/export identity.
- `storageIdentity`: измеренная disk/export binding identity; `storageIdentityFile` —
  canonical absolute runtime path вне store к root-owned readable witness file. Symlink
  ancestors и group/other write запрещены; до 257 bytes с точной identity и необязательным
  завершающим newline.
- `allowedComputerUuids`: 1–64 различных canonical lowercase AiiDA Computer UUIDs.
- `retentionPolicyId`, `retentionOwnerId`, `holdRef`, `accessBindingRef`: явная site policy,
  именованный owner и ссылки на evidence. Эти параметры и storage identity — непустые
  конечные identifiers до 256 символов. Defaults не придумывают admission/owner. Секреты
  в этих полях недопустимы.

Site witness — утверждение storage owner о принятой identity, а не обнаружение или
криптографическое доказательство backing disk. До включения измерьте фактические NFS
export/source и disk identity и свяжите witness с receipt. Замена диска за тем же server/export
требует новой identity и review binding. Одинаковый hostname и сам witness не доказывают
неизменность backing disk.

`QCL_NEGF_SAVED_RESULTS_BINDING_FILE` указывает generated store JSON с полями `namespace_id`,
`storage_identity`, `root` (всегда `/run/qcl-negf-saved`), `allowed_computer_uuids`,
`retention_policy_id`, `retention_owner_id`, `hold_ref`, `access_binding_ref`. Ссылки являются
private site metadata; этот файл не является browser DTO.

Runtime helper удаляет унаследованный binding, включая значение из старого `service.env`,
и устанавливает generated path только после проверки обоих точных NFSv4 mount/source,
read-only readable/searchable alias и root-owned site witness. Сравнение с APP, выбранным
при сборке OS, не требуется. Совместимое обновление APP сохраняет этот независимый read
provider. Missing mount, local directory, symlink root, foreign export и неверная storage
identity оставляют binding недоступным с явной причиной. Пустой локальный root не создаётся;
repository fallback отсутствует. Базовый API продолжает обслуживать другие routes, хотя
отсутствующий обязательный bind/mount может не дать запустить сам unit.

Consumer явно сопоставляет `namespace_id` и `storage_identity` каждого source с mapping,
а единственный AiiDA `computer_uuid` — с одним элементом `allowed_computer_uuids`. Platform
mapping не предоставляет CalcJob, result path, `remote_root`, `registration_source_id` или
per-child `admissions`. Их получает AiiDA через точный owner graph и независимо принятый
closed attempt. Глобальный `hold_ref` не доказывает остановку scheduler, отсутствие writers
или pruning, точную point/commit identity и hold для отдельного root. Из этого файла нельзя
синтезировать per-child admission.

Закрытые зарегистрированные roots хранятся бессрочно до отдельного явного распоряжения
именованного owner. Hold включает отрицательные результаты, metadata и полную declared
dependency closure, включая borrowed checkpoint/import source roots. Owner подтверждает,
что automatic cleanup, AiiDA remote-clean, workdir cleanup и export TTL не затрагивают held
roots. Live recovery pruning до регистрации остаётся за writer. Для научных roots новые
service, timer, TTL, migration, hardlink, deduplication и cleanup не устанавливаются.
Политика не гарантирует защиту от каждого администратора. Backup/restore и capacity
accounting — отдельные gates; historical repository mirrors, retry imports, scratch и backups
считаются отдельно.

Перед native использованием проверьте фактические numeric service UID/GID, directory
ancestry, ACLs и modes относительно Runner directory02750/file0640 и jobs0750. Одинаковые
usernames и `root_squash` недостаточны. World read и producer-wide read-only remount
недопустимы. Readable root metadata не доказывает доступ ко всем registered payloads.
Фактические storage/export identity, per-attempt hold, closed ownership, package binding,
read access и конечные child-resource checks остаются private native acceptance evidence.
Source wiring не доказывает L2 delivery без repository mirrors, завершение R04, backup и
научную приёмку. Активные scientific jobs не используются как access fixtures.

Локальные проверки: `tests/infrastructure/application-saved-results.nix`,
`tests/test_application_saved_results.py`, `tests/test_application_path.py` и
`tests/test_runtime_bindings.py`. Module fixtures используют реальные owning expressions с
synthetic package/file constructors; mount tests запускают настоящий bounded subprocess с
буквальными synthetic mount facts. Runtime tests отдельно проверяют APP switch, trusted
namespace, argv, timeout/output failure и сохранение original log. Эти проверки не доказывают
native NFS/VM/service readiness. `QCL_TEST_NIXPKGS` выбирает уже подготовленный source;
команда pytest не устанавливает пакеты и не выполняет bootstrap. Полная source evaluation
`tests/infrastructure/application-release.nix` — отдельная проверка и не является VM build.
