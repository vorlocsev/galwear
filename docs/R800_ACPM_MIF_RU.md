# SM-R800 — ACPM FlexPMU MIF (NON-RELEASE)

База Linux 4.19: 50db73fc799f20a7120a8b5f653b16cc123d856f.
Наследует development/r800-wakeup-mask-20261125.

Дефект: legacy getters читают flexpmu_dbg_base без проверки ioremap.
DT R800 data-size=0x400, полный layout DATA_LINE*DID_MAX=752 bytes.
Новый acpm_read_mif_state(count, request) проверяет выходы, наличие
карты и границы обоих 32-bit регистров; защищён IRQ-safe spinlock.
Публикация карты после probe, инвалидирование в remove. Проверка
DT длины свойств, выравнивания base и ioremap; ошибка debugfs root
освобождает карту. Legacy ABI сохраняет zero fallback, который
не является доказательством отсутствия MIF requests.

System suspend не входит в PSCI при недоступной pre-state; ошибка
post-state не затирает ошибку PSCI. Delta unsigned 32-bit допускает
единичное приращение с wrap, ноль не подтверждает MIF down.
Delta >1 считается неоднозначным (консервативное предположение,
не установленный аппаратный контракт). Счётчики не доказывают
физическое питание и могут быть изменены firmware независимо.

Три diff-секции проверены реконструкцией точного исходного текста.
Восемь статических условий и арифметика delta проверены; добавлены
восемь unittest. Полный Python/CI и kernel build не подтверждены.

Ограничения: readl не сообщает bus fault; два чтения не образуют
атомарный снимок firmware. Старый debugfs path и lifecycle
ioremap/remove (включая повторный probe, незакрытые debugfs handles)
нуждаются в отдельном аудите. Не заявляется аппаратная надёжность.
Следующий этап — lifecycle FlexPMU/debugfs, интеграция всех проверок
и проверка exact-head CI. Deep sleep отключён, safe_to_flash=false.
Только форк, без PR/main/upstream.
