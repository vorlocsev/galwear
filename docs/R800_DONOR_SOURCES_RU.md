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


Независимая упаковка overlay: UUID/seed теперь выводятся из canonical
JSON exact source SHA + выбранных 11 файлов, а не из полного component
manifest. Отдельный Ubuntu 24.04 runner заново компилирует 5 HAL,
стадирует 6 конфигураций и упаковывает EXT4. Сравнение с основным runner
требует совпадения состава, метаданных, инструментов mke2fs version и
SHA-256 образа. Между jobs передаются только JSON, без ELF и образов.
Не проверяет разные дистрибутивы или полную донорскую прошивку.


Перед запуском legacy build_vendor.sh можно выполнить rootless preflight:
```sh
python3 build/r800_vendor_recipe_preflight.py --base /path/to/base-vendor.img \
  --base-sha256 "$BASE_SHA256" --j4 /path/to/j4-vendor.img \
  --j4-sha256 "$J4_SHA256" --report /path/to/new-recipe-preflight.json
```
Проверяются 30 обязательных путей BASE, 71 J4 и три HIDL-группы,
без смешивания файлов разных доноров внутри группы. Используются приватные
read-only снимки образов, только debugfs stat. Содержимое рекурсивных
каталогов, ELF ABI, зависимости, SELinux и подлинность доноров не доказаны.
Это отдельный предварительный инструмент; legacy сборщик не изменён.


Строгий режим --check-elf проверяет выбранные обязательные bin/* и *.so
на ARM32 dynamic ELF, тип ET_DYN для библиотек, ET_EXEC/ET_DYN для
исполняемых файлов, отсутствие RPATH/RUNPATH. Сохраняются SHA-256,
DT_NEEDED и SONAME, но не извлечённые бинарники. build_vendor.sh теперь
обязательно вызывает этот режим до первого mount, по SHA-256 из
input-evidence.json. Неподходящий ELF блокирует соответствующий донор.
Это структурный gate, не полное разрешение зависимостей и не runtime.
Legacy loop-mount сборка на настоящих образах не проверена.


build_vendor.sh использует точный выбор HIDL-группы из recipe-preflight.json,
не повторяет выбор по одному лишь наличию файлов. Перед упаковкой выполняется
r800_merged_vendor_graph.py: фактические ELF в bin/lib, SHA-256, SONAME,
DT_NEEDED и граф всех локальных кандидатов /vendor/lib. Различные байты
с одинаковым SONAME, некорректные локальные провайдеры и невалидные ELF
блокируют упаковку. EXTERNAL_OR_MISSING пока диагностический статус:
без system/VNDK/APEX нельзя отличить отсутствующую библиотеку от внешней.
Это не доказательство замыкания символов или Android namespaces.


Merged vendor audit поддерживает --system-image FILE --system-sha256 HASH
и --include-apex. Используется существующий snapshot-based рекурсивный
анализ System/VNDK/Runtime APEX, но корнями теперь являются внешние
зависимости фактически объединённого vendor. VNDK version извлекается
из build.prop/default.prop; конфликт блокируется. Разные байты для
одного имени, найденного в vendor и системном графе, требуют review.
Для legacy build_vendor.sh опциональная пара R800_SYSTEM_IMAGE /
R800_SYSTEM_SHA256 включает строгий аудит с APEX до упаковки.
Без пары остаётся диагностический локальный граф NON-RELEASE.
Namespace precedence, symbol closure и реальные доноры не доказаны.


Merged vendor graph: --check-symbols собирает ограниченный transient
инвентарь импортов, экспортов и version requirements из реального
объединённого дерева и выбранных System/VNDK/APEX кандидатов. Использует
существующую проверку достижимых провайдеров, версий, TLS/non-TLS,
strong/weak и неоднозначности; неполнота или исчерпание бюджета дают
REVIEW_REQUIRED. При R800_SYSTEM_IMAGE/R800_SYSTEM_SHA256 legacy
сборщик теперь также включает --check-symbols. Отсутствие system
оставляет локальный структурный режим. Это не симуляция Android linker
namespace precedence и не доказательство загрузки HAL.


Merged vendor namespace audit: --linker-config FILE --linker-config-sha256
HASH или R800_LINKER_CONFIG/R800_LINKER_CONFIG_SHA256 для build_vendor.sh.
Проверяются пути поиска, секции executable roots, разрешённые namespace
links и shared_libs по выбранным ELF-кандидатам. Невалидная конфигурация,
неоднозначный или недоступный путь дают REVIEW_REQUIRED. Отдельно
unreached_vendor_objects показывает объекты, не охваченные цепочками
от bin/* (включая потенциальный dlopen HAL). Реальный порядок загрузки,
генерация linkerconfig, dlopen и runtime не проверены. Конфигурация
предоставляется явно; её происхождение не подтверждено.


ARM32 Bionic HAL probe: build/r800_hal_dlopen_probe.py compile проверяет
exact SHA и пять реально скомпилированных HAL, компилирует API28 probe.
Подкоманда run принимает явно подготовленный trusted ARM32 runtime
(linker, libc.so, libdl.so, libm.so, liblog.so) и JSON со SHA-256 каждого
файла, probe-dir и те же HAL. Каждый модуль запускается отдельно в
non-root bwrap --unshare-all с read-only гостевым деревом и qemu-arm-static.
Проверяются dlopen RTLD_NOW, dlsym HMI, tag, module id, API и указатель
methods->open, но сама функция open не вызывается. CI компилирует probe
и сохраняет только JSON; запуск с реальным runtime пока не проверен.
Не является проверкой оригинальных Android namespaces, драйверов или железа.


ARM32 runtime extraction из одного hash-pinned system.img (raw/sparse EXT4):
```sh
python3 build/r800_arm32_runtime_extract.py --system-image /path/to/system.img \
  --sha256 "$SYSTEM_SHA256" --output /path/to/new-arm32-runtime
```
Из Runtime APEX берутся bin/linker и lib/bionic/{libc,libdl,libm}.so,
из того же system — liblog.so. Сохраняются manifest SHA-256 и отчёт
происхождения; не используются NDK stubs. Выход подходит для
r800_hal_dlopen_probe.py run --runtime ... --runtime-manifest .../runtime-manifest.json.
Изолированный guest теперь размещает Bionic в /apex/com.android.runtime
и создаёт относительный /system/bin/linker alias. Тест извлечения использует
реальные синтетические EXT4/APEX, отдельный негативный тест отклоняет
не-ELF. Сам Android 11 runtime пока не получен и не запущен. Подлинность
и версия донорского runtime требуют отдельной проверки.


## Независимый Android 11 ARM32 reference

Google emulator RSR1.240422.001 из AOSP commit
cdaf21eb286931aa947e9ca3df00f89afe197713 имеет пустой abilist32;
не выбран для ARM32. Официальный GSI RP1A.200720.009 остаётся
локальным вариантом после получения с соблюдением условий Google.

Публичный phhusson/treble_experimentations v313 (Android 11), release
50839463, asset 46298761, system-roar-arm32_binder64-ab-vanilla.img.xz,
364782672 bytes — независимый reference, не Wear OS. GitHub не
предоставляет digest для этого legacy asset. CI получает его по
фиксированному release URL, ограничивает размер XZ и декомпрессии,
фиксирует наблюдаемый SHA-256, извлекает только пять runtime файлов
из packaged или flattened Runtime APEX + system liblog.
Публикуется только JSON. Это первое наблюдение, не независимая
проверка хеша, и не разрешение на выполнение стороннего ELF.
Динамический QEMU запуск в данном job отсутствует.


Первое наблюдение: CI 46025153522 / job 140594533250, архив получен,
XZ распакован, но отсутствовал simg2img. Хеши закреплены для повторной
проверки:
- XZ SHA-256 8685851758960e80110171249fd1ea005e88469457d31bd903a18ab1554eeb37
- sparse system.img SHA-256 2bf6cd3fa34b01b7d38456f02e1cb4694da80b8d2cb585a2a5b13adc361c812d, 1014649136 bytes.
Ubuntu 24.04 job теперь устанавливает android-sdk-libsparse-utils.
Повторная загрузка должна совпасть с обоими SHA-256 до извлечения ELF.
Это контроль неизменности относительно первого наблюдения, не подпись
разработчика и не независимая аттестация. Runtime не запускался.


Повторное наблюдение CI 46025927016 / job 140597194070: оба хеша
совпали, simg2img сработал, но libc.so отклонён по DT_NEEDED.
Android 11 Bionic libc/Android.bp явно перечисляет ld-android и libdl:
https://android.googlesource.com/platform/bionic/+/refs/heads/android11-release/libc/Android.bp
Разрешение ld-android.so теперь допустимо только если извлечённый
bin/linker сам имеет такой SONAME; отдельный .so не подставляется.
Другие неизвестные DT_NEEDED по-прежнему отклоняются с именами.
Фактическая зависимость reference будет подтверждена новым CI,
динамическая загрузка всё ещё не выполнялась.


CI 46028350588 / job 140605465244 подтвердил прохождение libc.so и
ld-android.so, но остановился на DT_NEEDED liblog.so -> libc++.so.
Минимальный reference runtime теперь включает шесть файлов: linker,
libc.so, libdl.so, libm.so, liblog.so и libc++.so. Последние две библиотеки
извлекаются из того же system image, не из NDK. Обязательны ARM32,
SONAME, SHA-256 и закрытый список DT_NEEDED; новый manifest содержит
все шесть файлов. QEMU размещает libc++.so в /system/lib. Список
разрешённых зависимостей компилируемых HAL не расширен. Тесты включают
отсутствие libc++.so. Фактическое замыкание и запуск ещё не подтверждены.


CI 46029031849 / job 140607780855: PHH_V313_ARM32_RUNTIME_STATIC_ONLY,
шесть файлов извлечены, packaged APEX, SONAME ld-android.so у linker,
все DT_NEEDED входят в замкнутый набор. Закреплены SHA-256 шести ELF,
raw system, APEX и APEX payload. Новый job arm32-hal-qemu на Ubuntu
22.04 независимо повторяет извлечение и компиляцию точного HEAD,
проверяет bwrap isolation и запускает пять отдельных HMI probes.
Публикуется только JSON, без исходных донорских ELF и образов.
Reference не является Wear OS; runtime authenticity не подтверждена.
Даже успешный HMI не проверяет methods->open, реальные namespaces,
Android boot, устройства или безопасность прошивки.


CI 46029789905 / job 140610408100, exact d228f16: реальный ARM32
Bionic reference загрузил все пять HAL, 5/5 HMI_ONLY_PASS, exit 0.
Следующая проверка --lifecycle выполняет после HMI один warm-up и
16 циклов: Audio/GPS/Lights open + проверка hw_device_t + close;
Audio также локальный mic mute roundtrip; HWC/Sensors должны
возвращать -ENOENT без объекта устройства при отсутствии fb0/SSP.
Перед запуском проверяется отсутствие аппаратных узлов, в каждом
цикле сравнивается число открытых FD в окне 0..255 после warm-up.
Старый HMI-only job step сохранён. Не вызываются GPS init, sensor poll,
PCM streams или brightness; не моделируется железо и не проверяется
полная утечка ресурсов за пределами окна FD. Новая lifecycle фаза
ожидает CI, NON-RELEASE.


CI 46030589352 / job 140613064800 exact e829405: 5/5 lifecycle PASS,
16 measured repeats per HAL, HWC/SSP absent -ENOENT, audio mute roundtrip.
Новый --lights-fixture запускает реальный Lights HAL отдельно в ARM32
Bionic QEMU с частным writable bind синтетического каталога brightness,
без host sysfs. Проверяются 6 RGB cases, cache skip, -ENOENT и retry того же
значения; реальная панель не проверена. Исправлена обработка errno и
short write (EIO), EINTR retry, close error. Остальной guest read-only;
сохраняются только JSON evidence. Новый сценарий ожидает CI.


CI 46031469433 / job 140616071775 exact c8b5f94:
ARM32_LIGHTS_SYNTHETIC_SYSFS_ONLY, 6 RGB + cache skip + missing retry PASS.
Новый --sensors-fixture вызывает реальный sensors HAL с private writable
SSP sysfs fixture: сохранение внешнего bit18 (262144), accel clamp 10 ms,
изменение delay, accel/gyro enable/disable, duplicate open EBUSY,
invalid handle EINVAL, malformed mask rollback, close ENOENT + retry,
16 повторных open/close с проверкой FD 0..255. Файлы фиксированной ширины
имитируют только операции read/write; input events, SSP MCU, Tizen
sensord concurrency и аппаратные датчики не проверяются. Новый CI pending.


CI 46032267044 / job 140618755991 exact 1b6a58a: synthetic SSP control PASS.
Новый --sensors-context использует отдельный guest FIFO /dev/r800_context,
реальный poll() с capacity=1 и canary за 104-byte event. Проверяются
W/D gestures, offbody duplicate suppression, два step counter handles,
step detector, монотонность после сброса P, malformed/NUL/overlong records,
disabled wrist gesture, flush metadata и сохранение total при reopen.
Тест ограничен 30s, guest изолирован; EV_REL/SSP MCU и реальные датчики
не проверяются. Новый CI pending.


CI 46033112247 / job 140621646487 exact 2fdc41a: synthetic context PASS.
Новый --sensors-evdev загружает тестовый libevdev-fixture.so только в
изолированном QEMU; ioctl EVIOCGNAME(63) сопоставляет шесть частных
FIFO по inode/device, остальные ioctl отклоняются. Производственный
Sensors HAL неизменён. Проверки: шесть физических handles, восемь
синтетических событий, точная timestamp assembly, значения и status,
нулевые отсутствующие компоненты, отказ нулевого давления, SYN_DROPPED
recovery и сохранение внешнего бита 30. Adapter не входит в payload.
Не тестируются реальные evdev driver, MCU, калибровка или аппаратные
показания. Новый CI pending.


CI 46033939650 / job 140624467942 exact ae61126: 6 EV_REL channels,
8 events, pressure reject and SYN_DROPPED PASS. Новый --gps-fixture
использует private Unix socket /oem/r800dev/gps.sock: START/TIME/LOC/
START reconnect/STOP, FIX, NMEA checksum, GSV/GSA/RMC satellite callback,
malformed/NUL/overlong rejection. STATUS barrier and atomics. HAL unchanged.
cleanup() не завершает reader, поэтому тест завершает процесс без dlclose.
Реальные Tizen GPSBridge, GNSS, cleanup safety и Wear OS не подтверждены.
Новый CI pending.


CI 46034793245 / job 140627359271 exact e7c079e: GPS synthetic bridge PASS.
GPS reader lifecycle: atomic running, nonblocking AF_UNIX connect,
poll + interruptible retry wait, shutdown to wake reader, pthread_join
before clearing copied callbacks. Duplicate init EBUSY, inactive start
ENODEV, cleanup idempotent, device close refuses join failure. Framework
create_thread_cb must return a joinable pthread_t; actual Wear OS wrapper
and concurrent/reentrant framework lifecycle calls remain unverified.
QEMU fixture now checks active STOP on cleanup, peer EOF, two reinits,
cleanup with missing bridge and dlclose only after successful test.
New CI pending; no actual GNSS.


CI 46036056045 / job 140631634438 exact 067e8cc: GPS cleanup PASS,
joined=3, reinit=2, active STOP, absent bridge and dlclose.
Новый --audio-fixture тестирует неизменённый Audio HAL без /dev/snd:
8 cycles, output 48k stereo, input 48k mono/stereo, invalid format negotiation,
duplicate stream and busy device close, invalid frame alignment, zero bytes,
16 silent captures with guard, playback fallback, unavailable positions,
FD count and HFP failure without mixer. Real PCM/mixer success, DSP, speaker,
microphone and HFP hardware remain unverified. New CI pending.


CI 46036845565 / job 140634296055 exact b903d64: no PCM fallback PASS,
8 cycles, 16 silent reads, mono/stereo and busy close. Новый --audio-pcm-fixture
использует test-only LD_PRELOAD libpcm-fixture.so, собранный с pinned tinyalsa
headers. Production HAL SHA unchanged. Проверяются partial transfers
127/113 frames, exact stereo output sequence, mono left extraction,
stereo capture, mute, presentation/capture positions, zero-progress write,
failed read silence and retry backoff. Адаптер считает 2000 output/4000 input
frames и 4 opens/closes; если interposition не сработает, тест не проходит.
Не тестируется tinyalsa implementation, ALSA ioctl, real mixer routing,
DSP or HFP success. New CI pending.


CI 46037698758 / job 140637184239 exact 290f2cb: synthetic PCM PASS,
2000 out + 4000 in frames. Extended fixture checks HFP 8/16 kHz SCO,
all four DSP PCM channels and exact open/prepare/start/stop order,
media suspended during call, renegotiation, idempotent enable/disable,
third start injected failure with reverse stop, mixer NORMAL rollback,
media resumes after both normal and failed call. Expected 10 starts/stops,
21 total opens/closes across PCM and HFP tests. Production HAL unchanged;
real Bluetooth stack, SCO signal, ALSA ioctl, codec and DSP unverified.
New CI pending.
