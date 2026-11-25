# SM-R800 — VSync IRQ accounting (NON-RELEASE)

База Linux 4.19: 50db73fc799f20a7120a8b5f653b16cc123d856f.
Ветка создана от актуальной development/r800-display-error-propagation-20261125:
на момент сверки эта ветка уже на 21 коммит впереди 1163a451.
Существующие TE reconnect, callback lifetime и HWC lifecycle сохранены.

DECON: изменение vsync.active и irq_refcount теперь сериализовано
одним vsync.lock; внутренние locked helpers не захватывают mutex
повторно. Underflow возвращает EIO, состояние не коммитится при ошибке.
Обычные временные wait-for-vsync references сохраняются.

HWC: software callbacks отделены от подтверждённого состояния TE ioctl.
Ошибка оставляет IRQ state unknown, повторный запрос того же режима
повторяет ioctl, EINTR обрабатывается. При close отключение запрашивается
даже при неизвестном состоянии. Timer fallback сохранён.

Проверены контекст и размеры 16 hunks секции DECON по точной базе.
Host C harness с вручную перенесённой точной функцией и эквивалентными
asserts скомпилирован cc -std=c99 -Wall -Wextra -Werror, выполнен PASS:
missing fd, EIO, EINTR, повторный enable, ошибка disable, retry, повторный
disable. Добавлен unittest, извлекающий функцию из исходника; три
существующих host harness адаптированы к новым границам извлечения.
Полный Python suite, NDK и kernel compile не запускались.

Ограничения: software fallback не доказывает TE IRQ или эмиссию панели.
Kernel ioctl по-прежнему глобален, не per-file; конкурирующие клиенты
и реальное IRQ поведение требуют runtime теста. Повторный запрос
восстановления осуществляется при следующем eventControl, не фоновым
таймером. Deep sleep по умолчанию запрещён, safe_to_flash=false.
Только форк, без PR/main/upstream и публикации firmware.
Следующее: проверить накопленный exact-head CI и исправить RX FIFO
после malformed пакетов, затем проверить panel ops и HWC restart.
