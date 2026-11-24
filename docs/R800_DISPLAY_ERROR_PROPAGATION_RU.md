# SM-R800 — DECON/DSIM error propagation (NON-RELEASE)

База Linux: 50db73fc799f20a7120a8b5f653b16cc123d856f.
Наследует development/r800-hwc-power-20261125.

Дефекты: два do/while(cnt--) могли пропустить тайм-аут, когда
cnt становился -1; бюджет ожидания повторно использовался для
нескольких packet batches. Исправлены ограниченные циклы,
ETIMEDOUT и отключение packetgo при ошибке. DCS display on/off
через cmd_rw теперь ждут опустошения FIFO. Неизвестная команда
возвращает EINVAL. DSIM read останавливается при ошибке отправки
или ожидания, освобождает hibernation block на timeout и проверяет
длину ответа до записи в буфер.

FBIOBLANK UNBLANK использует возвращающий ошибку synchronous
helper после flush предыдущей speculative work. LCD_ON notifier
перенесён после успешного decon_update_pwr_state. INVALID state
возвращает ENODEV; POWERDOWN при keep_panel_on возвращает
EOPNOTSUPP вместо ложного успеха. Interrupted vsync wait
передаёт errno. Асинхронный speculative worker сохранён.

Обе изменённые diff-секции реконструированы против точной базы,
8 статических условий проверены на сохранённом патче.
Добавлены 8 Python unittest; их полный запуск, NDK compile,
kernel build и exact-head CI не подтверждены.

Ограничения: empty FIFO не доказывает эмиссию панели;
не проверены реакция framebuffer clients на EOPNOTSUPP,
порядок notifier, конкуренция speculative wake, очистка RX FIFO
после повреждённого пакета, panel ops и возвраты register init.
Не добавлен автоматический аппаратный reset; исторический
timeout recovery сохранён. SurfaceFlinger restart recovery
и TE/VSync runtime остаются следующими блокерами.
Deep sleep отключён, safe_to_flash=false.
Только форк, без PR/main/upstream.
