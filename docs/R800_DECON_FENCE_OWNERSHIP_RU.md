# SM-R800 — DECON fence ownership (NON-RELEASE)

Kernel base: 50db73fc799f20a7120a8b5f653b16cc123d856f.
В r800-wearos.patch изменены dpu30/fence.c, decon.h и decon_core.c.
decon_create_release_fences возвращает int: сначала резервируются
все активные release FD, только затем вызывается fd_install.
Ошибка выделения освобождает только зарезервированные FD; кадр
не ставится в очередь. Ошибка создания retire fence возвращается
вызывающему коду, а после fput не продолжается диагностика fence.
Сравнены старые строки, номера, контекст и размеры всех 16 hunks
для трёх изменённых файлов с pinned source; расхождений не обнаружено.
Это не результат полного git apply --check и не компиляция ядра.

HWComposer передаёт release FD ядра напрямую вместо close+dup.
При старом/off-state ответе без release используется F_DUPFD_CLOEXEC
от retire; при отказе dup overlays отключаются для последующих кадров.
Отсутствие release при отказе dup для уже принятого кадра остаётся
риском; режим overlays теперь требует явного значения property 1.
Копирование и zero-copy клиентского target не менялись.

Семь тестов: извлечённая функция ядра с host-стабами и отказом
каждого выделения, неполный набор окон, проверки HAL и patch format.
Интеграционный CI требует полный pinned-source git apply --check.
Проверка copy_to_user EFAULT после fd_install пока не исправлена:
нужно спроектировать передачу FD без гонок и учесть частичный copy.
Отдельно нужны проверка actual kernel compile, sync_file runtime,
старого драйвера, donor adapter и аппаратная презентация.
Результаты CI не подтверждены. No flash, no release, no PR/main/upstream changes.
