# SM-R800 — PMUCAL save/restore snapshot (NON-RELEASE)

База ядра 50db73fc799f20a7120a8b5f653b16cc123d856f.
Продолжение development/r800-pmucal-rae-status-20261125.

Аудит исходных таблиц Exynos 9110 подтвердил условные save/restore
в VTS и системном SLEEP, CHECK_SKIP в DISPAUD, COND_CHECK_SKIP в SLEEP.
Исправлены обе функции RAE: перед новым save очищаются оба флага
всех элементов; restore потребляет флаг даже при skip или ложном
условии; skip_next локален текущему вызову; при WAIT timeout остаток
снимка инвалидируется. Намеренный fallthrough аннотирован.

Проверена реконструкция изменённой секции из закреплённой базы.
Добавлен host unittest с извлечением обеих функций из полного контекста
патча. Эквивалентный локальный C harness с fake registers успешно
скомпилирован cc -std=gnu99 -Wall -Wextra -Werror и прошёл assertions
для устаревшего снимка, повторного restore, skip, conditional skip,
timeout, новой попытки save и изменившегося условия. Полный запуск
репозиторного теста, git apply --check полного патча, kernel build и CI
не подтверждены.

Это не доказывает безопасный аппаратный откат: безусловные WRITE и WAIT
по-прежнему выполняются при restore; автоматический replay снимка
после ошибки не разрешён. Общий RAE используется другими SoC, их
поведение не проверено. Следующий этап — отмена suspend между syscore
и PSCI, корректный выбор early wakeup и очистка power-mode hint.
Глубокий сон выключен, safe_to_flash=false. Только форк, без PR/main/upstream.
