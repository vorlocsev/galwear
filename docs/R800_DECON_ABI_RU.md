# SM-R800 — DECON compat ioctl ABI (NON-RELEASE)

Сверены decon.h, decon_core.c и fence.c из pinned kernel
50db73fc799f20a7120a8b5f653b16cc123d856f.
decon_compat_ioctl передаёт cmd и compat_ptr(arg) в decon_ioctl без
трансляции структуры; ARM32 userspace обязан совпадать с ARM64 kernel.

Выделен r800_decon_abi.h с 16 compile-time assertions:
rect 16, frame 24, DPP params 48, window 200, payload 808 bytes,
ioctl 0x432846d1; проверяются offsets acquire 20, release 24,
format 40, dpp 48, src 144, dst 168, protection 192, compression 193.
Значения проверяются compile-time assertions в CI ARM32/ARM64.
CI извлекает декларации из точного kernel SHA и компилирует их
и userspace mirror для ARM32 и ARM64 NDK. При несовпадении
останавливает сборку HAL. Модель заменяет kernel enum на int,
dma_addr_t на uint64_t; фактические typedef/enum values и
конфигурация сборки требуют дополнительной проверки.
Добавлено пять synthetic tests извлечения и отклонения неверных входов.


## Транзакция WIN_CONFIG

В текущем патче GalWear уже разделены резервирование, публикация и установка
release/retire FD. При неудачной резервации или copy_to_user отменяются
только ещё не установленные FD; кадр не ставится в очередь. Worker получает
свою ссылку до передачи файловых ссылок. Off-state возвращает signaled fence,
что не доказывает физический вывод кадра.

Добавлен host-only тест всей фактической patched decon_set_win_config и трёх
release-функций. Моделируются отказ kzalloc, retire FD, prepare, каждого из
трёх release FD, частичный copyout, off-state и пустой кадр. Проверяются
отсутствие установленных FD при отказе, отмена резервов, баланс файловых
ссылок, освобождение подготовленных буферов, неизменность update region,
отсутствие queue/hiber и порядок copyout перед fd_install. Успешный путь
проверяет передачу FD и worker reference. Модель не воспроизводит реальные
kernel races, DMA, timeline или аппаратную презентацию. CI нового теста
ещё не подтверждён. safe_to_flash=false.

## Retire FD / errno

Патч сохраняет исходный errno get_unused_fd_flags при первом отказе и
при отказе после резервирования FD 0–2. Резервирование release возвращает
тот же errno вместо принудительного EMFILE. CI применяет секцию fence.c
к точному pinned blob и компилирует реальные функции в host-only harness:
20 сценариев, в том числе ENOMEM, EMFILE, откат низких FD и баланс ссылок
retire. Фактические kernel FD table races и sync_file не проверены.

## Acquire wait errno

Сохраняется отрицательная ошибка dma_fence_wait_timeout, нулевой результат
преобразуется в -ETIMEDOUT. Command-mode status не перезаписывает уже
полученную ошибку ожидания; неожиданно активный fence после положительного
wait даёт -EIO. Video-mode policy (проверка только wait) не меняется.
12 host-only сценариев проверяют pinned оригинал и применённый патч.
Не изменены decon_update_regs, rollback буферов и политика сигнализации
retire. Физическая проверка sync_file, владения буферами и вывода не проведена.
