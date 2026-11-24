# SM-R800 — HAL shared library link gate (NON-RELEASE)

Ветка наследует интеграционный CI. Добавлена линковка четырёх
armeabi-v7a HAL для Android API 28 через фиксированный NDK r27c:
audio.primary.r800.so, gps.r800.so, sensors.r800.so, hwcomposer.r800.so.

Оригинальный tinyalsa sync_ptr patch по указанным в Audio HAL путям
не найден. Новый патч реконструирован по tinyalsa v2.0.0
(1c5fb68ced57d838f2b7ecd0c00bc1fefc9ab60d) и исходнику
sound/core/pcm_compat.c в pinned kernel 50db73fc799f20a7120a8b5f653b16cc123d856f.
В compat handler отсутствие APPL/AVAIL_MIN означает запись control из
userspace. Для non-MMAP PCM kernel readi/writei управляет appl_ptr:
патч принудительно запрашивает текущие значения ядра в pcm_sync_ptr.
Для PCM_MMAP флаги не изменяются. Это новая кандидатная реализация,
не доказанная эквивалентность утраченного патча.

Сценарий сначала компилирует четыре HAL, затем копирует pinned
tinyalsa в scratch через git archive, проверяет git apply --check,
применяет патч и компилирует статическую библиотеку без plugins.
Линковка запрещает unresolved references, задаёт SONAME и скрывает
символы статической библиотеки. Проверка ELF: ARM ELF32 ET_DYN,
экспорт HMI, SONAME, allowlist DT_NEEDED, отсутствие RPATH/RUNPATH
и TEXTREL. Добавлены восемь синтетических тестов readelf.

Артефакты CI — только JSON с SHA256, SHA коммита и идентичностью запуска.
Объекты и .so не публикуются. Успешная линковка не доказывает
совместимость Android linker namespace, структуру HAL ABI или
работоспособность PCM, и не является допуском к прошивке.
Результаты CI пока не подтверждены. Далее: проверить exact-head CI,
исправить ошибки NDK/UAPI и провести полную ABI сверку с donor vendor.
