# SM-R800 — wakeup mask и MIF (NON-RELEASE)

Ветка наследует PMUCAL integration. База Linux 4.19:
50db73fc799f20a7120a8b5f653b16cc123d856f.

Для non-SICD: валидация mode/override, границ DT массивов, выравнивания
и отсутствия дублированных offset; snapshot всех mask до записи.
Проверяется код записи, чтения и точное readback. При ошибке
восстанавливаются все затронутые mask в обратном порядке, включая
неуспешную запись; CAL enter не вызывается. Ошибка rollback передаётся
выше; восстановление не гарантировано. SICD сохраняет быстрый путь
без readback и rollback, но возвращает ошибку записи.

DT R800 имеет два wakeup mask (0x610/0x618) и один EINT offset (0x60c).
Проверено наличие CONFIG_EXYNOS_PMU=y и CONFIG_EXYNOS_FLEXPMU_DBG=y.
INFORM4 при ошибке доступа логируется как unavailable; счётчики MIF
печатаются unsigned. Проверены контекст двух изменённых diff-секций
и восемь статических условий; добавлены восемь Python unittest.
Запуск Python/CI, полный git apply --check и kernel build не подтверждены.

Следующий блокер: acpm_get_mifdn_count и acpm_get_mif_request в
exynos-flexpmu-dbg.c напрямую читают flexpmu_dbg_base без проверки
успеха ioremap/границ. Необходимо отдельное checked API и обработка
отсутствующей карты, не трактовать нулевой счётчик как ошибку.
Возврат успешной записи mask не подтверждает доступность всех wake
sources; PMU raw MMIO, hardware, deep sleep не проверены.
safe_to_flash=false. Только форк, без PR/main/upstream.
