# SM-R800 — CPU idle policy (NON-RELEASE)

База Linux 4.19: 50db73fc799f20a7120a8b5f653b16cc123d856f.
Наследует development/r800-system-suspend-policy-20261125.

Старое отключение states_usage[k].disable после cpuidle_register
не защищало окно ранней инициализации и последующую запись sysfs.
Добавлен независимый default-deny bool r800_allow_deep_idle (0600).
При выборе deep state без разрешения используется WFI и возвращается
фактический индекс 0. Проверка повторяется после подготовки; при
отмене вызывается post_idle(..., 1), PSCI пропускается.
Проверяются границы индекса, результат cpu_pm_enter и результат
подготовки Exynos. Положительный ненулевой PSCI result преобразуется
в -EBUSY, а не учитывается как успешный idle.

Android helper требует отдельный CPUIDLE_DEEP marker, закрытый gate,
readback state1/disable для обоих CPU и readback разрешения gate.
При неуспехе предпринимается закрытие gate и отключение state1.
SLEEP и CPUIDLE_DEEP не взаимозаменяемы.

Контекст секции проверен реконструкцией по точной базе, восемь
статических условий проверены на сохранённых файлах. Добавлено
восемь unittest. Полный unittest, shell runtime, kernel compile,
точный sysfs путь параметра и аппаратные испытания не подтверждены.

Ограничения: проверка перед PSCI не устраняет все гонки при изменении
параметра привилегированным процессом. Проверка не покрывает другие
пути runtime PM, аппаратные ошибки CAL и s2idle. Следующий этап:
проверка HWC/display blank/unblank, Android init handover и обновление
интеграционного CI на актуальную ветку. Deep idle и системный suspend
по умолчанию запрещены. safe_to_flash=false.
Только форк, без PR/main/upstream.
