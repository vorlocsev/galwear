# R800 — integrated evidence gate (NON-RELEASE)

Исправлен ранее ошибочный вызов compile-only вместо link smoke.
Установлены BusyBox и обязательный сбор всех JSON отчётов.
Job integration-evidence проверяет результаты regression, HAL object
compile, HAL link, DECON dual-ABI, pinned kernel patch check.
Проверяются exact commit, run ID, attempt для четырёх отчётов;
для kernel patch preflight — хеши patch, config, DTS и pinned base
(этот старый формат не содержит run ID). Артефакты получаются
из текущего workflow, не из произвольного старого запуска.
Семь synthetic tests проверяют отсутствие, несогласованность,
пропуски и stale evidence. Не доказывают выполнение реального CI.
При повторе только failed jobs возможен mismatch попыток:
для итоговой проверки следует повторить все jobs.

CI не подтверждён: доступный connector возвращает только PR runs,
combined status пуст, публичный Actions API/web недоступен из сеанса.
Workflow отсутствует на main, поэтому новый workflow_dispatch нельзя
считать доступным без изменения default branch. Main не меняем.
Push-trigger оставлен на существующей ветке, без новой PR/ветки.
Для проверки откройте Actions с фильтром этой ветки и пришлите
ссылку на run с последним SHA. Если run отсутствует, проверьте,
включены ли Actions для форка. Не требуется локальная сборка.
Kernel repeatability остаётся отдельной необязательной проверкой;
итоговый integration evidence явно kernel_compiled=false.
No binaries, no flash, no upstream changes.
