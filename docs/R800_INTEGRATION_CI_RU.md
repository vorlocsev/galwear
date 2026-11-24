# SM-R800 — интеграционный CI (NON-RELEASE)

Ветка наследует накопленные изменения до 0500ef018e53a027a55c9b06150480f373e19d29.
Работа только в форке, без PR, без изменений main/upstream.

## Три независимых направления

1. Regression: полное unittest discovery tests/test_*.py, синтаксис
   shell и формат kernel patch. JSON фиксирует SHA, run ID, attempt,
   количество найденных/выполненных тестов, ошибки, пропуски.
   Пропуск или expected failure не считается полным PASS.
2. HAL compile: четыре полных C translation units
   audio_r800.c, gps_r800.c, sensors_r800.c, hwcomposer_r800.c.
   Android NDK r27c (27.2.12479018), ARM32 armeabi-v7a, API 28
   (выбран уровень Android 9 donor vendor), NEON.
   Tinyalsa v2.0.0 headers: 1c5fb68ced57d838f2b7ecd0c00bc1fefc9ab60d.
   Проверка ARM ELF, JSON с SHA256 исходников и объектов.
   Это compile-only, не link и не готовые .so. Патч tinyalsa sync_ptr
   нужен для настоящей сборки Audio HAL, но его файл пока не найден.
3. Kernel: существующий two-run workflow доступен из интеграционного
   через workflow_call. Два независимых Image с read-only /init,
   сравнение hashes и APK inventory. Запуск только по явному параметру
   kernel_repeatability=true при workflow_dispatch; не включён
   автоматически на каждом коммите.

HWComposer source найден в src/hal/hwcomposer_r800.c; его не меняли.
Полная загрузка Wear OS, динамический linker, VINTF runtime, Tizen
GNSS bridge ARM/glibc, аппаратные испытания и secure boot не проверены.
CI публикует только JSON evidence, не firmware и не .o.
Результаты сборки и тестов следует подтверждать по exact-head run,
не по наличию workflow. safe_to_flash=false.
