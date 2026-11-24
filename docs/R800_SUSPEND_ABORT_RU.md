# SM-R800 — отмена suspend до PSCI (NON-RELEASE)

База Linux: 50db73fc799f20a7120a8b5f653b16cc123d856f.
Наследует development/r800-pmucal-save-restore-20261125.

В kernel/power/suspend.c после успешного syscore_suspend возможны
TEST_CORE или pm_wakeup_pending: suspend_ops->enter пропускается,
но syscore_resume вызывается. Старое is_early_wakeup могло быть ложным
или относиться к предыдущему циклу.

Исправлено:
- На подготовке сбрасываются состояние PSCI и early wakeup.
- Выбранный режим (обычный/USB L2) сохраняется до восстановления.
- Успешный prepare фиксируется; resume потребляет флаг однократно.
- Без попытки PSCI вызывается early wakeup, а не normal exit.
- Ошибка PSCI сохраняет отрицательный errno; положительный код
  нормализуется в -EBUSY. Успех требует сохранённой проверки MIF.
- Маркер 4 фиксирует CAL prepare до PSCI.
- PMUCAL отклоняет отрицательный mode, очищает power-mode hint на
  ошибках выполнения последовательностей и при завершении normal exit.

Две diff-секции реконструированы с контролем контекста, строк и
смещений против точной базы. Девять статических условий проверены
на сохранённом патче; обновлены девять unittest. Полный запуск
Python, git apply --check, компиляция ядра и CI не подтверждены.

Ограничения: очистка hint не откатывает частично выполненный enter;
early wakeup не доказан на физическом устройстве. Поведение других
SoC и SICD требует интеграционной проверки. Следующий этап:
exact-head regression и полный kernel compile, аудит ошибок
wakeup mask/readback и MIF. Deep sleep выключен; safe_to_flash=false.
Только форк, без PR, изменений main/upstream и публикации firmware.
