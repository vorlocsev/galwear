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


Опция --include-selinux добавляет read-only инвентарь выбранных файлов
vendor/system sepolicy и HIDL hwservice_contexts. Сравниваются записанные
plat_sepolicy_and_mapping.sha256 идентификаторы и наличие точных имён
HIDL интерфейсов, проверяется заголовок MLS policy (19..31).
Сравнение идентификаторов не пересчитывает хеши CIL/mapping.
Контексты wildcard, regex-переходы, system_ext/product/odm, компиляция
CIL, neverallow, checkfc и enforcing runtime остаются вне этой проверки.


Компиляция явно выбранных CIL-файлов с SHA-256, без загрузки политики:
```sh
python3 build/r800_donor_cil_compile.py --input /path/to/plat.cil "$PLAT_SHA256" \
  --input /path/to/vendor.cil "$VENDOR_SHA256" --report /path/to/new-cil-report.json
```
Передаются все нужные CIL и mapping в заданном порядке; автоматического
подбора отсутствующих файлов нет. secilc запускается с MLS и policyvers 31,
neverallow не отключается. CI проверяет синтетическую допустимую политику
и намеренное нарушение neverallow. Компиляция не подтверждает полноту
Android policy, подлинность доноров или совместимость с ядром часов.


Дополнительная проверка буквальных security contexts через libsepol:
собрать host-only helper командой
cc -std=c11 -Wall -Wextra -Werror build/r800_context_check.c -lsepol -o /path/to/context-check
и передать --context-checker /path/to/context-check --contexts FILE SHA256
при компиляции CIL. Проверяются user/role/type/MLS по тому же бинарному
policy; отрицательная fixture содержит неизвестный тип. Это не AOSP
checkfc: правила regex, Android type attributes, seapp и реальные
переходы доменов не проверены.


Для проверки штатным AOSP checkfc по тому же скомпилированному policy
передаются --checkfc PATH --checkfc-sha256 SHA256 и один или несколько
--checkfc-context KIND FILE SHA256. KIND: file, property, service,
hwservice, vndservice. Проверки выполняются без -e и без загрузки
policy. Отчёт содержит digest инструмента, policy и каждого context,
код возврата и ограниченную диагностику. CI проверяет контракт
передачи аргументов с mock; реальный AOSP host checkfc должен быть
получен из существующей pinned AOSP сборки. Подлинность tool и
полнота контекстов не устанавливаются одним digest.


Штатная pinned AOSP сборка build/r800_aosp_sepolicy_build.sh после
сборки checkfc запускает r800_aosp_checkfc_matrix.py. Отдельный отчёт
checkfc-matrix.json содержит выбранные контексты system/vendor/system_ext/
product/odm, отсутствующие файлы, результаты каждого режима и отрицательный
тест неизвестного типа. Требуются file/property/service/hwservice;
vndservice может отсутствовать и отмечается отдельно. Запуск только
на подготовленной disposable AOSP среде. Это stock AOSP, не донорская
политика SM-R800; обычный CI проверяет контракт с mock.


Для статической проверки перехода домена конкретного HAL:
```sh
python3 build/r800_donor_domain_transition.py --policy /path/to/sepolicy \
  --policy-sha256 "$POLICY_SHA256" --source init --executable HAL_EXEC_TYPE \
  --target HAL_DOMAIN --report /path/to/new-transition.json
```
Типы берутся из реальной политики и контекстов, не угадываются.
sesearch проверяет конкретный type_transition и необходимые unconditional
allow transition/execute/entrypoint. Условные правила и переходы через
атрибуты в type_transition требуют дополнительной проверки. CI компилирует
синтетическую политику, затем проверяет разрешённый и неподходящий домен.
Это не проверка полного запуска HIDL, ограничений MLS, binder или enforcing.


Для статического аудита выбранной пары клиент/HIDL:
```sh
python3 build/r800_donor_hidl_permissions.py --policy /path/to/sepolicy \
  --policy-sha256 "$POLICY_SHA256" --server HAL_DOMAIN --client CLIENT_DOMAIN \
  --manager hwservicemanager --service-type HWSERVICE_TYPE \
  --report /path/to/new-hidl-report.json
```
Имена типов берутся из реальных контекстов и политики. Проверяется
консервативный профиль из 13 unconditional allow для add/find,
call/transfer. Это не исчерпывающий набор правил для всех вариантов HIDL;
callback, fd use, устройство /dev/hwbinder, MLS constraints и регистрация
runtime не проверены. Синтетическая CI fixture удаляет find и должна
получить REVIEW_REQUIRED ровно по этому правилу. Рабочие политики
не изменяются.


Дополнительные параметры HIDL audit: --device-type HwbinderDeviceType
добавляет 15 проверок chr_file open/read/write/ioctl/map для server,
client и manager. --kernel-config FILE --kernel-config-sha256 SHA256
проверяет IPC, COMPAT, список binder/hwbinder/vndbinder через существующий
kernel_evidence. CI --fixture-device использует синтетический config
и policy, отрицательный тест удаляет только ioctl клиента. Это не
доказательство наличия node, DAC/ueventd, ioctl xperm или обмена IPC.
Фактическую конфигурацию ядра и тип устройства необходимо предоставить.


Rootless EXT4 smoke: build/r800_compiled_overlay_ext4.py принимает
проверенное дерево компонентов exact SHA и создаёт только overlay-test.ext4
(64 MiB) с 5 HAL и 6 конфигурациями в целевых путях vendor. mke2fs -d,
e2fsck -fn и debugfs dump проверяют упаковку без mount/root. CI удаляет
образ и сохраняет только JSON. Не содержит donor HIDL, policy, radio,
и не является готовым vendor.img. SELinux xattrs не проверяются.


EXT4 overlay test дополнен rootless установкой uid/gid=0, 0644 для
файлов и 0755 для каталогов (кроме служебного lost+found).
security.selinux записывается с NUL: vendor_file для HAL и каталогов,
vendor_configs_file для конфигураций, согласно историческому рецепту.
Повторный read-only аудит проверяет inode type, права, владельца,
точные xattrs, отсутствие security.capability и содержимое. Эти метки
синтетические, не результат matchpathcon оригинальной политики.
Отрицательный тест проверяет подмену mode, gid и удаление xattr.


Эксперимент воспроизводимости EXT4: UUID и hash_seed выводятся из SHA-256
манифеста, задана фиксированная эпоха, сортировка путей и отключены lazy
inode/journal initialization. CI выполняет две упаковки в отдельных
каталогах, сравнивает SHA-256, байты, выбранные inode metadata и сохраняет
JSON независимо от результата. Это проверка same-host, не cross-host,
и не сборка полноценного vendor.img. При несовпадении CI блокирует этап.
