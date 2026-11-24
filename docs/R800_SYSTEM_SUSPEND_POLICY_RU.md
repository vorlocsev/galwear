# SM-R800 — системный suspend: политика разрешения (NON-RELEASE)

База Linux 4.19: 50db73fc799f20a7120a8b5f653b16cc123d856f.
Наследует development/r800-power-integration-20261125.

В проверенных путях src/hal/power_r800.c и src/hal/suspend_r800.c
отдельные реализации не обнаружены. Android helper описывает
Power HAL как no-op default. Наличие и версия HAL в закрытых
system/vendor images не подтверждены.

Ранее защита system suspend зависела от userspace wake_lock:
при ошибке записи helper только логировал предупреждение.
Теперь exynos-pm имеет независимый default-deny bool parameter
r800_allow_system_suspend (0600), проверки в platform begin,
syscore suspend и перед PSCI. .valid не изменён, чтобы не скрыть
режим mem навсегда при регистрации platform suspend ops.
Существующий CAL fault latch сохраняется.

Android helper берёт wake lock до конфигурации, закрывает kernel
gate и проверяет readback. Только явный SLEEP marker, подтверждённые
PD overrides и подтверждённый kernel gate разрешают освобождение
wake lock. При ошибке opt-in предпринимается отключение gate,
возврат wake lock и сброс PD overrides. Старое ядро без параметра
не получает разрешение от helper; его собственная политика
не может быть гарантирована.

Проверены контекст изменённой секции diff и восемь статических
условий на сохранённом коде. Добавлено восемь Python unittest.
Компиляция, shell runtime, Python unittest, exact-head CI и
аппаратные испытания не подтверждены.

Ограничения: это не реализация Android Power/Suspend HAL,
не блокировка s2idle, CPU idle или runtime PM и не доказательство
защиты от privileged runtime override. Путь sysfs параметра
и его права требуют проверки на собранном ядре. Deep sleep
по умолчанию запрещён, safe_to_flash=false.
Следующий этап — независимый ранний запрет глубокого CPU idle
и проверка взаимодействия с display/HWC и Android init.
Только форк, без PR/main/upstream.
