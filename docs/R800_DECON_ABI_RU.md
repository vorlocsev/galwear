# SM-R800 — DECON compat ioctl ABI (NON-RELEASE)

Сверены decon.h, decon_core.c и fence.c из pinned kernel
50db73fc799f20a7120a8b5f653b16cc123d856f.
decon_compat_ioctl передаёт cmd и compat_ptr(arg) в decon_ioctl без
трансляции структуры; ARM32 userspace обязан совпадать с ARM64 kernel.

Выделен r800_decon_abi.h с 16 compile-time assertions:
rect 16, frame 24, DPP params 48, window 200, payload 808 bytes,
ioctl 0x432846d1; проверяются offsets acquire 20, release 24,
format 40, dpp 48, src 144, dst 168, protection 192, compression 193.
Значения вычислены из исходных деклараций, не подтверждены CI.
CI извлекает декларации из точного kernel SHA и компилирует их
и userspace mirror для ARM32 и ARM64 NDK. При несовпадении
останавливает сборку HAL. Модель заменяет kernel enum на int,
dma_addr_t на uint64_t; фактические typedef/enum values и
конфигурация сборки требуют дополнительной проверки.
Добавлено пять synthetic tests извлечения и отклонения неверных входов.

Аудит fence.c: release fences для BUFFER получают отдельные FD
одного sync_file; текущий overlay HAL закрывает их и дублирует
retire FD, что создаёт лишние аллокации. В error path kernel
decon_create_release_fences вызывает put_unused_fd для ранее
установленных через fd_install дескрипторов. Этот путь требует
отдельного анализа и исправления; не менять вслепую. Также
decon_ioctl может вернуть EFAULT после установки fence FD при
неудачном copy_to_user. Успешный ioctl не доказывает физическую
презентацию: off-state path создаёт немедленно signaled fence.

Release/retire ownership и zero-copy алгоритм не изменены.
Donor HWC adapter ABI и аппаратный runtime не проверены.
CI результатов пока нет. Без firmware, PR, main/upstream changes.
