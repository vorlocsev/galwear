# Сборка компонентов GalWearOS SM-R800

Статус: экспериментальное дерево компонентов, не прошивка.

## Локальная сборка на Linux x86_64

Требуются Android NDK r27c, JDK с javac --release 8, Android API 30
android.jar, Build Tools 30.0.3, Python 3.10+, git, bash, GCC ARM EABI,
binutils, libc6-dev-armel-cross, qemu-user, flex, bison и pkg-config.
Использовать новые каталоги вне исходного дерева.

```sh
sh build/r800_build_hals.sh "$NDK" "$WORK/hal"
sh src/vendor/libbt/build.sh "$NDK" "$WORK/bt"
sh build/r800_build_tools.sh "$NDK" "$WORK/tools"
sh src/tools/keepwifi/build.sh "$ANDROID_JAR" "$BUILD_TOOLS" "$WORK/keepwifi"
sh build/r800_build_busybox.sh "$WORK/busybox"
sh build/r800_build_wifi_tools.sh "$WORK/wifi"
python3 build/r800_stage_components.py \
  --hal-dir "$WORK/hal" --vendor-sources src/vendor \
  --tools "$WORK/tools" --bluetooth "$WORK/bt" \
  --keepwifi "$WORK/keepwifi" --busybox "$WORK/busybox" --wifi "$WORK/wifi" \
  --output "$WORK/components" \
  --source-sha "$(git rev-parse HEAD)"
```

Результаты: vendor-overlay/, payload/, unlinked/gpsbridge.o и
component-evidence.json. Последний хранит хеши и размеры файлов.
GPSBridge.o не является исполняемым GPSBridge.
Статические Wi-Fi-утилиты в payload/bin заменяют прежние вызовы через musl.
Поддержка WPA2-PSK проверена только на уровне компиляции и флагов версии;
ассоциация с точкой доступа, работа драйвера и SELinux не проверены.
Старое дерево root с musl не включается в новый payload. Дерево tzlite,
библиотеки Tizen и отдельный recovery ramdisk остаются необходимыми.
Совместимость Wi-Fi с реальным драйвером ещё не подтверждена.

## Сведение локальных входов payload

После генерации ресурсов через src/tools/charger/mkassets.sh и извлечения
радиофайлов из чистого Tizen ext4 через build/r800_extract_ext4.py:

```sh
python3 build/r800_prepare_payload_inputs.py \
  --components "$WORK/components" --assets "$WORK/assets" \
  --radio "$WORK/radio" --output "$WORK/partial-payload" \
  --source-sha "$(git rev-parse HEAD)"
```

Проверяются точный SHA исходников, список обязательных собранных файлов,
размеры, хеши, ELF и DEX. Отчёт payload-inputs-evidence.json указывает
категорию источника каждого файла. Сценарий не создаёт прошивку, не копирует
пользовательские данные и не принимает решение о совместимости доноров.
Для проверки подлинности требуются независимые доказательства происхождения.

## Что ещё требуется

- Чистые локальные образы Samsung combination, Wear OS system, base vendor и J4 vendor.
- Полные совместимые группы HIDL и библиотеки системных зависимостей.
- Локальные Tizen glibc 2.24: libc.so.6, libdl.so.2, libpthread.so.0 и ld-linux.so.3 для линковки GPSBridge.
- Оригинальные firmware Broadcom, подготовленные display assets и другие
  сторонние утилиты/деревья из требований r800_payload_candidate.py.
- Проверенные NZIT/PIT и восстановление, отдельная аппаратная приёмка.

Не использовать резервные копии с учётными данными, сетевыми профилями или
персональными данными. CI публикует только отчёты, не бинарники.
Хеши и успешная компиляция не доказывают совместимость на устройстве.
safe_to_flash=false.

## Разделение режимов ядра

`build/kbuild-native.sh` использует только read-only initramfs и изоляцию хранилища. Это диагностический Image, а не образ для Android handover. `src/initramfs/build.sh` компилирует экспериментальный handover отдельно; его запуск не проверен. Не объединять результаты этих двух режимов в заявление о готовности прошивки.

Сборщики Bluetooth и KeepWifi ещё не подтверждены фактической компиляцией на интеграционной ветке. Перед созданием полного локального дерева необходимы их проверенные результаты. См. `../ROADMAP.md`.
