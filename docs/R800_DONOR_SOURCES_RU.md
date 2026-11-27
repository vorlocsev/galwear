# Источники донорских образов SM-R800

Сведения перенесены из донорской ветки по состоянию на 25 ноября 2026 года; внешние источники повторно не проверялись. Ссылки предназначены для получения локальных
донорских файлов, а не для прошивки устройства. Бинарники не добавляются в Git.

| Компонент | Кандидат | Источник / доказательство | Статус |
|---|---|---|---|
| Wear OS system | Pixel Watch r11btwifi, RWDC.230905.003 (Android 11) | [Google factory images](https://developers.google.com/android/images-watch), [таблица SHA-256](https://developers.google.cn/android/images-watch?hl=en) | Официальная запись подтверждена; архив не получен |
| Samsung Combination | FT40_R800XXU1ARI2 | [Firmware Drive](https://firmwaredrive.com/folders/6902) | Сторонний каталог, подлинность не подтверждена |
| J4 vendor | SM-J400F J400FXXU6BTD2 (Android 9) | [Samsung changelog](https://doc.samsungmobile.com/SM-J400F/001799180920/eng.html), [каталог SamFW](https://samfw.com/firmware/sm-j400f/ILO) | Версия ОС подтверждена; совместимость конкретной сборки не проверена |
| Tizen | SM-R800 stock firmware | [Samsung update history](https://doc.samsungmobile.com/SM-R800/001692180913/eng.html) | Точная донорская версия библиотек/firmware требует проверки |
| Base vendor | TicWatch | Модель и build ID в текущем README не определены | BLOCKED: не выбирать случайный образ |

## Pixel Watch

Использовать только Bluetooth/Wi-Fi вариант r11btwifi. LTE r11 имеет другой SHA.
SHA-256 официального ZIP:
`eb4977308b8fe6a25bbe0c4918d95e6e79b9f05ae608f48ac2f04b65c42f0b52`.

После получения архива с соблюдением условий Google:

```sh
python3 build/r800_extract_pixel_factory.py \
  --archive /path/to/local-factory.zip --output /path/to/new-pixel-donor
```

Сценарий проверяет полный хеш, читает только вложенный image ZIP нужной модели,
извлекает только system.img, super.img, vendor.img при наличии, сохраняет
хеши и формат каждого файла. Не запускает flash-all, не извлекает userdata,
bootloader или другие разделы. Не изменяет оригинальный архив.
Это исходные доноры, не подготовленные образы R800. Sparse/super требуют
отдельного безопасного разбора, адаптация Android не выполнена.

## Блокеры

Оригинальные архивы отсутствуют в CI. Прямое скачивание из сторонних каталогов
не автоматизировано: не подтверждены содержимое, хеши и условия доступа.
Не использовать дампы с персональными данными или секретами устройств.
Точная версия базового TicWatch vendor остаётся неизвестной.
safe_to_flash=false.

В интеграционной ветке приёмка локальных файлов выполняется `build/r800_donor_preflight.py`. Обязателен также `tizen/ld-linux.so.3`. Структурный PASS не подтверждает происхождение и аппаратную совместимость.


## Отдельное извлечение библиотек GPSBridge

Из чистого локального raw ext4 Tizen rootfs с независимо установленным SHA-256:

```sh
python3 build/r800_extract_ext4.py --profile tizen-gps \
  --image /path/to/rootfs.img --sha256 "$ROOTFS_SHA256" \
  --output /path/to/new-gps-donor
python3 build/r800_gps_acceptance.py --out /path/to/new-gnss-report \
  --ndk /path/to/ndk-r27c --donor /path/to/new-gps-donor/tizen
```

Профиль читает только четыре явно заданных регулярных файла glibc 2.24,
включая ld-2.24.so (сохраняется как ld-linux.so.3). Не извлекает
радиофайлы или пользовательские данные. Отсутствие или неоднозначность
библиотеки блокирует успешное завершение извлечения. Иные пути не
угадываются. Структурное извлечение не доказывает версию ABI, подлинность
или совместимость: перед использованием требуется проверка источника и
статический GPS link gate. QEMU — отдельная явно запрошенная фаза.


## Идентификация кандидата TicWatch vendor

Исторический рецепт в коммите `0f865fa6adf01f85d8a5d18ccb8748441c0bb317`
указывает `/mnt/d/r800/donor/x/images/vendor.img`, но не модель и не build ID.
Для локального raw ext4 образа:

```sh
python3 build/r800_extract_ext4.py --profile vendor-identity \
  --image /path/to/vendor.img --sha256 "$VENDOR_SHA256" \
  --output /path/to/new-vendor-identity
```

Отчёт ext4-evidence.json содержит разрешённые свойства модели, производителя,
build ID, fingerprint, SDK и ABI, наличие VINTF и инвентарь трёх групп HIDL
(Wi-Fi, sensors, GNSS), а также статическую информацию об извлечённых ELF.
Конфликт свойств, неполный набор и невалидные ELF требуют проверки.
Это не проверка содержимого VINTF, подлинности образа, замыкания зависимостей
или аппаратного runtime. Извлечённые файлы остаются локальными.


Профиль vendor-identity дополнительно разбирает ограниченный по размеру
UTF-8 device VINTF manifest. Проверяются точные объявления HIDL 1.0
(hwbinder, default) для Wi-Fi, supplicant, sensors и GNSS. Поддерживаются
формы version/interface/instance и fqname. DTD и объявления сущностей
отклоняются. Отсутствие нужных деклараций требует review; наличие
не подтверждает FCM-совместимость, зависимые библиотеки или запуск HAL.
Фрагменты manifest и наследование версий пока не моделируются.


Проверка identity_inventory требует наличия модели, device, build ID и
fingerprint. Разбирается стандартная структура Android fingerprint;
расхождения с явно указанными brand/device/build ID/release требуют review.
SDK проверяется только на числовой формат. Это консервативный фильтр,
а не каталог поддерживаемых моделей: законные отличия свойств могут
потребовать ручного разбора. Отсутствие других файлов рецепта также
остаётся блокером полного профиля. Даже IDENTITY_FIELDS_PRESENT не
подтверждает происхождение, конкретный исходный TicWatch или совместимость.


Для каждой группы HIDL отчёт direct_dependencies классифицирует DT_NEEDED
по уже извлечённому ARM32 инвентарю: кандидат из той же группы, из другой
группы, отклонённый (ELF/SONAME) или вне выбранного инвентаря. Проверяется
явный путь vendor/lib; lib/hw не считается каталогом поиска. RPATH/RUNPATH
требуют отдельного разбора. Список external_names — вход для следующего
аудита VNDK/system, а не утверждение, что библиотека отсутствует в образе.
Даже DIRECT_INVENTORY_ONLY не означает замыкание зависимостей. Это
диагностический отчёт, код завершения профиля пока не зависит от него.


Профиль vendor-identity также строит ограниченный граф транзитивных
DT_NEEDED кандидатов непосредственно из того же проверенного read-only
EXT4 snapshot. Поиск только в vendor/lib, без lib/hw и lib64; новые
библиотеки не сохраняются в выходное дерево. Лимиты: 128 объектов,
128 MiB прочитанных ELF, глубина 16, 4096 рёбер. Циклы не приводят
к повторному обходу. Отсутствие кандидата означает необходимость
проверки system/VNDK, а не доказательство отсутствия зависимости.
Некорректные имена, ELF, SONAME, RPATH и превышения лимитов требуют review.
Граф диагностический; его статус не подтверждает Android namespace,
символьную совместимость, запуск HAL или возможность прошивки.


Для сопоставления внешних имён DT_NEEDED можно дополнительно передать
чистый raw EXT4 Android system:

```sh
python3 build/r800_extract_ext4.py --profile vendor-identity \
  --image /path/to/vendor.img --sha256 "$VENDOR_SHA256" \
  --system-image /path/to/system.img --system-sha256 "$SYSTEM_SHA256" \
  --output /path/to/new-vendor-system-report
```

Поиск ограничен /lib и /system/lib, а также vndk-N/vndk-sp-N при
наблюдаемом числовом ro.vndk.version. Кандидаты проверяются на ARM32
ET_DYN, SONAME и RPATH/RUNPATH; неоднозначность требует review.
Оригиналы и приватные снимки проверяются на изменения. Выход содержит
только метаданные дополнительных библиотек. Без --include-apex не анализируются APEX; namespace и symbol binding не моделируются.
Диагностический статус не является release gate; исходный код завершения
vendor-identity не изменён.


Граф system_candidate_graph рекурсивно обходит однозначных кандидатов
system/VNDK. Опция --include-apex дополнительно проверяет только
com.android.runtime.apex и com.android.vndk.vN.apex (N из наблюдаемого
ro.vndk.version) в /apex и /system/apex на том же snapshot. Читается
только apex_payload.img из ZIP; поиск ARM32 в /lib/bionic и /lib
Runtime, /lib VNDK. Архив и payload остаются временными; отчёт содержит
их хеши и происхождение кандидатов. Отсутствие/неоднозначность пакета
требуют review. CAPEX, версионные имена, другие APEX, подписи,
AVB, активация и linker namespaces не подтверждены.


В vendor-identity добавлен symbol_candidate_audit: временный ограниченный
инвентарь ELF imports/exports объединяет выбранные vendor/system/APEX
графы. Сопоставление использует существующий анализатор symbol_candidates,
включая слабые импорты, версии, TLS и неопределённые провайдеры. Не более
32768 записей и 4 MiB имён символов; превышение лимита требует review.
Наличие кандидата не доказывает правильный порядок загрузки Android,
видимость namespace, relocation, dlopen или запуск HAL. Отчёт остаётся
диагностическим, safe_to_flash=false.


Опциональные --linker-config /path/to/ld.config.txt и
--linker-config-sha256 принимают явную конфигурацию с заданным хешем.
Для ARM32 проверяются сопоставление executable section, search.paths
и разрешённые прямые links/shared_libs в графе уже исследованных ELF.
CONFIG_PATH_MATCHES_ONLY означает только совпадение путей с выбранными
кандидатами, не отсутствие других файлов, порядок загрузки, isolation,
permitted paths, реальное разрешение symlink или активацию APEX.
Происхождение конфигурации остаётся неподтверждённым. Без параметров
этот дополнительный аудит не запускается.
