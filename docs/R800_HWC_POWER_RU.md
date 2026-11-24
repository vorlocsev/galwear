# SM-R800 — HWC power policy (NON-RELEASE)

Наследует development/r800-cpuidle-policy-20261125.

Исходный HWC мог считать FBIOBLANK успешным, хотя DECON с
r800_keep_panel_on=1 игнорирует POWERDOWN; DCS unblank error
возвращался как успех. Ошибки doze resume и setPowerMode
не препятствовали обновлению software state. Idle thread мог
отключить DECON между resume и present.

Исправлено: DCS по умолчанию, real blank только при явном opt-in
helper с readback kernel gate; ошибки и короткая запись DCS
возвращаются вызывающему. Mode коммитится только при успехе,
неизвестное состояние блокирует present до явной смены режима.
Frame submission и power transitions сериализованы doze_lock;
сохраняется обработка acquire/release fences. Automatic doze suspend
выключен по умолчанию; DOZE_SUSPEND без opt-in эмулируется обычным
DOZE (не доказательство аппаратного suspend). Idle deadline monotonic,
обновляется только после успешной отправки кадра. CPU-copy pan
ошибка не засчитывается как кадр. Startup marker записывается лишь
при успешных ioctl; после restart сохраняется последний кадр и
требуется явный power transition.

Проверены восемь статических условий на сохранённых файлах;
добавлены восемь unittest, но Python suite и NDK compile не запущены.
Проверено исходное поведение DECON и DSIM sysfs store закреплённой
базы: cmd 2/3 передают ошибку dsim_cmd_sysfs_write. Успешный ioctl
или DCS write сам по себе не доказывает видимую эмиссию панели.

Риски: удержание doze_lock на протяжении submission/fence wait
требует runtime проверки latency; composer restart может не получить
ожидаемый явный power transition. Права sysfs и SELinux, actual
Ambient, TE, яркость, panel recovery, lifecycle worker threads и
совместимость HWC2 adapter не проверены. Следующий этап — NDK compile
и тесты с fake ioctl/write, затем аудит DECON/DSIM и restart recovery.
Deep sleep отключён, safe_to_flash=false. Только форк, без PR/main/upstream.
