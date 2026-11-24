# SM-R800 — HWC acquire fence and framebuffer safety (NON-RELEASE)

Изменён src/hal/hwcomposer_r800.c. На CPU-copy пути прежний код
продолжал читать gralloc после таймаута poll, ошибки или HUP.
Теперь wait_fence потребляет FD один раз и разрешает чтение только
при успешном POLLIN без POLLERR/POLLHUP/POLLNVAL. При ошибке кадр
пропускается. EINTR также приводит к пропуску, без бесконечного ожидания.
Путь произвольного fallback-слоя после закрытия его acquire fence
удалён; без FB target предыдущий кадр сохраняется.

Проверены границы framebuffer и 32bpp, вычисления размера двух половин
переведены на 64 бита. Ошибка pan не меняет front и не считается
успешной презентацией. При успешном gralloc lock с NULL выполняется
unlock. Убрано чтение полей недействительного handle в диагностике.
Doze timer обновляется только после успешной презентации (включая overlay).

Восемь тестов: фактическая функция wait_fence компилируется host cc,
готовый/не готовый pipe, HUP, invalid FD, отсутствие fence;
остальные проверяют исходник. Pipe не является sync_file, поэтому
семантика реальных GPU/DECON fences и ownership остаются непроверенными.
HWC set при пропуске кадра по-прежнему возвращает 0; реакция Android
adapter не проверена. Для однобуферного FB копирование само по себе
может изменить видимые пиксели до успешного pan. Нельзя обещать
сохранение предыдущего кадра в этом случае.

Не изменены kernel ioctl layout, heuristic layer stride, native_handle
ABI, zero-copy release/retire contract и аппаратный doze. Эти вопросы
требуют сверки с pinned kernel и donor adapter. CI настроен, результаты
ещё не подтверждены; никакие firmware или HAL .so не публикуются.
Main, upstream и реальные часы не затронуты.
