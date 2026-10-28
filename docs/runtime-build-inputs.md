# Исходники runtime-пакетов

`lib.mkApplication` использует общий `uv.lock` и отдельный native source каждого Python-пакета.
Версии компонентов по-прежнему определяют gitlinks корневого репозитория. Отфильтрованные Nix inputs
управляют пересборкой; они не заменяют полный source graph или provenance выпуска.

В каждый пакет входят `pyproject.toml`, `README.md`, `LICENSE` и весь `src`. Поэтому схемы, package
data и встроенные ресурсы сохраняются. Portal дополнительно получает `hatch_build.py` и frontend:
исходники, lock, build recipe и tests, участвующие в полной проверке frontend receipt.
Подготовленные `node_modules` и выходной `dist` не входят в source. Сборка frontend остаётся
отдельной native деривацией; её проверенные assets копируются в wheel. Проверка receipt не
отключается.

Capture runtime выбирает Results CLI и его зависимости из того же PythonSet. Он не зависит от
Portal, AiiDA или полного application environment. Изменение Results или Contracts может изменить
capture и solver; изменение только Portal не должно менять эти деривации.

Исследовательский каталог получает собственный input: `config`, `literature`, `docs`, `README.md`,
`LICENSE` компонента Research. Документация здесь является доступным пользователю содержимым
каталога, поэтому входит в runtime. Проверка совместимости приложения получает отдельный
неизменяемый Python-файл. Регистрация AiiDA entry points и проверка совместимости выполняются при
сборке как прежде.

## Проверка изменений

Для изменения списка ресурсов сначала проверьте native wheels из выбранных Nix sources и наличие
всех package data. Затем сравните `.drv` для исходного checkout и его отдельной копии с единственной
поправкой. Root предоставляет `tests/capture_runtime_eval.nix`; evaluation не собирает и не
устанавливает приложение. Подготовленный depot передавайте явно.

Ожидаемая матрица для source inputs:

| Изменение                                          | Capture  | Solver   | Julia |
| -------------------------------------------------- | -------- | -------- | ----- |
| Только документация Root, Core, Runner или Results | тот же   | тот же   | та же |
| Runtime Core или Runner                            | тот же   | меняется | та же |
| Runtime Results                                    | меняется | меняется | та же |
| Runtime Portal                                     | тот же   | тот же   | та же |

`README.md` входит в metadata wheel и может менять соответствующий пакет. Изменение frontend receipt
inputs может менять frontend и полный Portal wheel. Полный application может меняться независимо от
capture. Совпадение `.drv` подтверждает границу зависимостей, но не заменяет package tests,
установленный service или synthetic acceptance.

Список source inputs не даёт права повторно использовать произвольный Julia depot. Проверки
совместимости depot, Manifest и версии Julia сохраняются; изменение их формата и повторное
использование после изменения source graph требуют отдельной проверки производителя и потребителей.
