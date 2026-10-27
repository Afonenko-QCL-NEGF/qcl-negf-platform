# Свидетельства и границы публикации

[Общий отчёт](../README.md)

Срез исполнения: CP70, updated_at=2026-10-27T06:46:18Z. Метаданные PR проверены позже отдельно; их
observation UTC указан в индексе. Источники разного возраста не приравниваются к одному live
наблюдению. Период относится к кампании, начатой EXEC19октября; это не оценка непрерывного рабочего
времени человека или модели.

## Навигация

- [Все75карточек](task-register.md).
- [Проверенные102PR](pr-index.md).
- [Операции1–500](operation-ledger-1.md), [501–1000](operation-ledger-2.md),
  [1001–1445](operation-ledger-3.md).
- [Научные snapshots и память](science-snapshots.md).
- [Счётчики и единицы](metrics-ledger.md).
- [Hash-каталог оригиналов и Git identities](source-catalog.md).
- [Короткие проекции APP/DOC04/worker gates](gate-excerpts.md).
- [Подробный независимый аудит времени](cost-audit.md).
- [Точный source audit памяти](memory-source-audit.md) и
  [независимый runtime review](memory-runtime-review.md).

## Происхождение проекций

Coordination journal содержит1445records. Первые862 были архивированы и представлены ссылкой
archive/index; при извлечении проверены SHA256 архива и каждого locator. Восстановлены исходные
ID/state/wall_seconds; две legacy строки используют operation вместоid. Абсолютные пути и сетевые
адреса удалены; полный журнал/receipts/private inventory не опубликованы. В публичном ledger
показаны только явные ID/state, одноимённое numericwall_seconds, receiptSHA и ссылкиGitHub. Нет
key/token bytes, raw shell/SSH commands, scientific arrays или depots.

Публичные тексты — пересказ и численные проекции. Их нельзя выдавать за raw bytes с указанным hash.
Для independent replay приватного native/science evidence оператору понадобятся оригиналы, доступ к
которым GitPR не предоставляет. Публичные исходники/PR доступны по ссылкам. Локальные checks docsPR
проверяют Markdown, ссылки, составdiff и отсутствие приватных данных; они не запускают solver,
окружение, build или finalCI.

`completed`, `GUEST_TERMINAL`, nativeunitexit0 и merge означают разные события. Научная сходимость,
physical gates, discretization, validation, native activation, browser acceptance и release остаются
отдельными уровнями. Исторический UNKNOWN не означает новый unknownsubmit: последующие reconcile
entries сохраняются, дублировать submit нельзя.
