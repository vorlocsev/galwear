# Управляемая локальная сборка SM-R800

`build/r800_donor_manager.py` принимает один закреплённый SHA-256 JSON
манифест вместо длинного списка параметров сборщика. Это режим
NON-RELEASE, без скачивания, прошивки и публикации бинарников.

## Подготовка

Разместить разрешённые локальные входы в отдельном каталоге, не внутри
Git checkout и не в его родительском каталоге. Указать относительные
пути, полные SHA-256, exact HEAD и XTRA ABI. Значения ниже обозначают
места для реальных проверенных хешей; пример не является готовым манифестом.

```json
{
  "schema": "galwear-r800-local-donor-manifest-v1",
  "source_sha": "EXACT_HEAD_40_HEX",
  "inputs": {
    "kernel": {"path":"compiled/kernel","sha256":"KERNEL_EVIDENCE_SHA256"},
    "components": {"path":"compiled/device","sha256":"COMPONENT_EVIDENCE_SHA256"},
    "system": {"path":"pixel/system.img","sha256":"RAW_SYSTEM_SHA256"},
    "base": {"path":"vendor/base.img","sha256":"BASE_VENDOR_SHA256"},
    "j4": {"path":"j4/vendor.img","sha256":"RAW_J4_SHA256"},
    "effects": {"path":"vendor/libeffectsconfig.so","sha256":"EFFECTS_SHA256"},
    "tizen": {"path":"tizen/rootfs.img","sha256":"RAW_TIZEN_SHA256"},
    "closure": {"path":"tizen/closure","sha256":"CLOSURE_MANIFEST_SHA256"},
    "ndk": {"path":"tools/android-ndk-r27c","tools_sha256":{
      "source.properties":"REVISION_SHA256",
      "clang":"CLANG_SHA256",
      "ld.lld":"LLD_SHA256",
      "llvm-readelf":"READELF_SHA256"
    }}
  },
  "evidence": {
    "system": {"path":"pixel/raw-donor-evidence.json","sha256":"PIXEL_REPORT_SHA256"},
    "j4": {"path":"j4/stock-donor-evidence.json","sha256":"J4_REPORT_SHA256","archive_sha256":"J4_ARCHIVE_SHA256"},
    "tizen": {"path":"tizen/stock-donor-evidence.json","sha256":"TIZEN_REPORT_SHA256","archive_sha256":"TIZEN_ARCHIVE_SHA256"}
  },
  "xtra_abi": 0,
  "assets": null
}
```

Опциональные assets: объект path/sha256 для каталога и
assets-evidence.json. Все три отчёта обязательны в managed mode;
старый CLI сборщика остаётся доступен для диагностики.
Для managed build обязательны четыре SHA-256 в tools_sha256. Версия NDK
должна быть 27.2.12479018 (r27c); проверяются source.properties и три
исполняемых файла GPSBridge до и после сборки. Старый манифест без этих
pins допускается только в managed check с явным NOT_SUPPLIED.
Локальные наблюдаемые хеши можно вывести без запуска компилятора:

```sh
python3 build/r800_ndk_pins.py --ndk /local/galwear-inputs/tools/android-ndk-r27c
```

Сверять pins с доверенной копией NDK; сам вывод хешей не доказывает
подлинность. Проверка не охватывает остальные файлы NDK и библиотеки хоста. Модель base vendor, источник effects, права обработки
и подлинность доноров требуют отдельной проверки. XTRA ABI 0 здесь
только пример, фактическое значение должно соответствовать входам.

## Проверка без сборки

```sh
python3 build/r800_donor_manager.py \
  --workspace /local/galwear-inputs \
  --manifest /local/galwear-inputs/manifest.json \
  --manifest-sha256 "$MANIFEST_SHA256" \
  --source-sha "$(git rev-parse HEAD)" \
  --output /local/new-development-output \
  --mode check
```

Успешный результат MANAGED_INPUT_PINS_MATCH_ONLY означает совпадение
локальных входов и отчётов, не готовность Android, kernel, recovery
или HAL. Проверка не создаёт выходной каталог.
Явный --mode build передаёт тот же набор входов существующему сборщику,
который сам проверяет хеши и отчёты до/после сборки. Для сборки нужна
подготовленная изолированная Linux-среда с зависимостями legacy vendor.
Новый менеджер не обеспечивает готовность окружения и не проверяет
полноту либо подлинность NDK. Исходный манифест сохраняется побайтно в evidence/managed-donor-manifest.json.
Development Readiness сверяет его SHA-256, exact HEAD, pins всех входов,
трёх отчётов и архивов Samsung, выбранных инструментов NDK, XTRA ABI и
assets с итоговым отчётом сборки. Статус SAVED_MANIFEST_CHAIN_ONLY означает
согласованность сохранённой цепочки, но не повторную проверку оригинального
рабочего каталога и не независимую подпись. При отсутствии манифеста
старый диагностический режим явно отмечается NOT_SUPPLIED.

Android 15 и EROFS не добавляются в текущий Android 11 сборщик.
Не использовать результат для прошивки. safe_to_flash=false.


## Base vendor identity

Managed check выполняет read-only аудит закреплённого base vendor и Effects.
MANAGED_BASE_IDENTITY_REVIEW_REQUIRED (exit 2) означает неполные или
противоречивые буквальные свойства, в том числе отсутствие признака ARM32.
Managed build в таком случае останавливается до сборки. Группы HIDL и
VINTF остаются информационными, поскольку рецепт допускает J4-провайдеры.
Совпадение или различие Effects с членом base vendor не является
доказательством происхождения и не блокирует сборку само по себе.
Успешная сборка сохраняет evidence/base-vendor-identity.json и его pin;
Readiness повторно вычисляет сводку из компактного сохранённого отчёта
извлечения и сверяет исходные pins base/effects и exact HEAD.
SAVED_LITERAL_IDENTITY_CHAIN_ONLY не означает повторную проверку оригинального
образа, исторического совпадения, VNDK-совместимости или запуска HAL.
Старый прямой диагностический режим остаётся NOT_SUPPLIED.


## Обязательный контракт среды managed build

В манифест добавить объект верхнего уровня:

```json
"environment": {
  "lock": "environment/linux-assembly-lock.json",
  "lock_sha256": "LOCK_SHA256",
  "probe": "environment/synthetic-mount-probe.json",
  "probe_sha256": "PROBE_SHA256",
  "elf": "environment/linux-host-elf-lock.json",
  "elf_sha256": "ELF_REPORT_SHA256"
}
```

Оба отчёта должны относиться к exact HEAD; probe должен ссылаться на SHA-256 lock,
содержать все семь положительных синтетических проверок и подтверждённую очистку.
Подготовка описана в R800_LINUX_ASSEMBLY_ENVIRONMENT_RU.md. Запускать реальную пробу
только отдельно в выделенной VM. Managed check и build не запускают пробу повторно.
Перед и после управляемой сборки проверяются текущие выбранные системные инструменты,
Python, Ubuntu, PATH, наблюдаемые root/CAP_SYS_ADMIN/loop-control и неизменность обоих
файлов. Отчёты сохраняются в evidence; Readiness сверяет их хеши, манифест и статусы.
Старый манифест без environment доступен только для диагностики (NOT_SUPPLIED).
Старые результаты managed build без отчётов требуют повторной сборки для нового gate.
Сохранённая проба не является подписанной аттестацией и не доказывает текущую
работоспособность mount, воспроизводимость или полную изоляцию VM.


### Static host ELF lock

Managed build дополнительно требует linux-host-elf-lock.json и его SHA-256
в environment. Отчёт должен относиться к тому же exact HEAD и SHA-256 Linux lock,
иметь SELECTED_HOST_ELF_CANDIDATES_ONLY без проблем и содержать полный достижимый
статический граф выбранных инструментов. Перед и после сборки граф повторно
инвентаризируется без запуска исследуемых ELF. Readiness проверяет сохранённые
корни, зависимости, загрузчик, допустимые пути, pins и достижимость объектов.
Манифест без ELF отчёта доступен только для диагностики; предыдущие managed
результаты требуют повторной сборки для нового gate. Если реальная Ubuntu VM
покажет нестандартные пути или неоднозначность, сборка блокируется до анализа.
Это не подтверждает фактическую загрузку, dlopen, Python extensions или
воспроизводимость. safe_to_flash=false.
