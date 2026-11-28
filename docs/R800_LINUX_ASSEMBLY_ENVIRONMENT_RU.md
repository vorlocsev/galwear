# Linux-среда для локальной сборки GalWearOS SM-R800

## Контракт первого этапа

Ubuntu 24.04 x86_64 — выбранная кандидатная среда, поскольку она уже
используется в r800-integration-ci. Это не готовый воспроизводимый
контейнер или проверенная сборочная VM.

Использовать отдельную доверенную Linux VM, не основной рабочий компьютер.
Существующий vendor builder требует root, private mount namespace, loop
устройства, EXT4 и SELinux xattrs. Не подключать часы и не предоставлять
VM физические диски для сборки. Оригинальные образы хранить отдельно.
Обычный непривилегированный контейнер не считается эквивалентом VM.

Базовые пакеты-кандидаты (версии не закреплены этой командой):

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends \
  python3 git bash coreutils grep sed findutils tar util-linux \
  llvm attr e2fsprogs
```

Компиляция kernel/device components — отдельный этап. Его существующие CI
используют также ARM toolchain, clang/lld, dtc, make, flex, bison и другие
зависимости. Они не входят в контракт сборки из уже скомпилированных
компонентов. NDK r27c закрепляется отдельно через r800_ndk_pins.py.

## Снимок выбранных инструментов

Из чистого checkout нужной рабочей ветки, с системным Python:

```sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
HEAD_SHA=$(git rev-parse HEAD)
/usr/bin/python3 build/r800_linux_assembly_environment.py \
  --mode capture --source-sha "$HEAD_SHA" \
  > /local/galwear-inputs/linux-assembly-lock.json
sha256sum /local/galwear-inputs/linux-assembly-lock.json
```

Снимок закрепляет Ubuntu release ID, архитектуру, Python version,
exact HEAD и SHA-256 выбранных системных исполняемых файлов.
Инструменты должны разрешаться в /usr/bin или /usr/sbin. Сохранить lock
и его хеш вне репозитория; получать pins только из доверенной среды.
Наблюдаемые хеши не доказывают подлинность пакетов.

## Проверка до сборки

```sh
/usr/bin/python3 build/r800_linux_assembly_environment.py \
  --mode check --source-sha "$HEAD_SHA" \
  --lock /local/galwear-inputs/linux-assembly-lock.json \
  --lock-sha256 "$LOCK_SHA256"
```

Проверка сравнивает выбранные файлы и сообщает наблюдаемые effective UID,
CAP_SYS_ADMIN и наличие loop-control. Если хотя бы одна предпосылка
отсутствует — HOST_PREREQUISITES_REVIEW_REQUIRED (exit 2).
Даже при совпадении pins статус SELECTED_HOST_TOOLS_MATCH_PREREQUISITES_UNTESTED
не подтверждает private mount namespace, loop mount или SELinux xattrs.
Никакие монтирования, компиляторы и гостевые бинарники не запускаются.

Следующие работы: выполнение синтетической проверки на отдельной VM,
привязка environment lock и отчёта пробы к Donor Manager,
проверка динамических библиотек и закрепление версии сборочной VM.
Текущий lock не является обязательным gate существующего сборщика и не
доказывает побайтовую воспроизводимость.

NON-RELEASE. safe_to_flash=false.


## Синтетическая проверка возможностей VM

Только в отдельной доверенной VM, с явно подтверждённым запуском.
Не использовать основной компьютер, часы или подключённые физические
диски. Скрипт не принимает путь к донорскому образу или устройству.

```sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
/usr/bin/python3 build/r800_synthetic_mount_probe.py \
  --workspace /local/galwear-inputs \
  --lock /local/galwear-inputs/linux-assembly-lock.json \
  --lock-sha256 "$LOCK_SHA256" --source-sha "$HEAD_SHA" \
  --confirm-dedicated-vm
```

Проба создаёт собственный временный образ EXT4 (32 МиБ), запускает
private mount namespace, проверяет RW loop mount, SELinux security.selinux,
перенос xattrs через tar, сохранность данных при RO remount, umount и
отсутствие loop-ассоциации, затем выполняет e2fsck -fn.
При невозможности подтвердить очистку временный каталог сохраняется;
автоматическое отключение чужих loop-устройств запрещено.

SYNTHETIC_EXT4_MOUNT_XATTR_PASS_ONLY относится только к данному тесту VM.
Реальные mount/xattr проверки ещё не выполнены в рамках разработки;
модульные тесты используют заглушки. Проба не проверяет сборку vendor,
изоляцию от враждебного root, оригинальные доноры или железо.


## Статический ELF lock системных зависимостей

Из той же VM и чистого exact-head checkout, с ранее закреплённым lock:

```sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
/usr/bin/python3 build/r800_linux_host_elf_lock.py \
  --mode capture --lock /local/galwear-inputs/linux-assembly-lock.json \
  --lock-sha256 "$LOCK_SHA256" --source-sha "$HEAD_SHA" \
  > /local/galwear-inputs/linux-host-elf-lock.json
sha256sum /local/galwear-inputs/linux-host-elf-lock.json
/usr/bin/python3 build/r800_linux_host_elf_lock.py \
  --mode check --lock /local/galwear-inputs/linux-assembly-lock.json \
  --lock-sha256 "$LOCK_SHA256" --source-sha "$HEAD_SHA" \
  --report /local/galwear-inputs/linux-host-elf-lock.json \
  --report-sha256 "$ELF_REPORT_SHA256"
```

SELECTED_HOST_ELF_CANDIDATES_ONLY означает наличие единственных статических
кандидатов DT_NEEDED и PT_INTERP в стандартных каталогах, совпадение
исполняемых файлов с Linux lock и повторную проверку хешей объектов.
Неоднозначные, отсутствующие, нестандартные и неподдержанные ELF-кандидаты
требуют HOST_ELF_REVIEW_REQUIRED (exit 2). Не использовать ldd.
Отчёт не моделирует ld.so.cache, glibc-hwcaps, RPATH/RUNPATH, dlopen,
Python extension imports и фактическую загрузку библиотек. Скриптовые
обёртки и нестандартные пути пока требуют отдельного анализа.
Отдельный NDK lock сохраняется. Этот ELF lock обязателен для managed build; диагностический режим
может работать без него. Readiness проверяет сохранённый статический граф,
но это не доказывает воспроизводимость. Проверка на реальной Ubuntu VM ещё не выполнена.


## Наблюдение разрешения библиотек glibc

Только в доверенной отдельной VM, от непривилегированного пользователя.
Сначала получить Linux lock и статический ELF lock для того же exact HEAD.
Не передавать донорские или гостевые бинарники; загрузчик может отображать
системные библиотеки в память, поэтому этот режим не является sandbox.

```sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
/usr/bin/python3 build/r800_linux_loader_observation.py \
  --lock /local/galwear-inputs/linux-assembly-lock.json \
  --lock-sha256 "$LOCK_SHA256" \
  --elf /local/galwear-inputs/linux-host-elf-lock.json \
  --elf-sha256 "$ELF_REPORT_SHA256" --source-sha "$HEAD_SHA" \
  --confirm-trusted-vm \
  > /local/galwear-inputs/linux-loader-observation.json
```

Проверяются хеши выбранных ELF-объектов и загрузчика, состояние
ld.so.cache и отсутствие непустого ld.so.preload. В очищенном окружении
glibc --list сопоставляет наблюдаемые пути с закреплёнными статическими
кандидатами каждого инструмента. Адреса ASLR не входят в идентичность.
Непривязанные, отсутствующие или неоднозначные объекты отклоняются.
Статические ELF без PT_INTERP и DT_NEEDED отмечаются отдельно.

GLIBC_LIST_SELECTED_PROVIDERS_MATCH_ONLY не означает проверку нормального
запуска, secure-execution, dlopen, Python extensions или воспроизводимости.
Этот отчёт пока диагностический, не является обязательным gate.
Реальная VM и её glibc не проверены в рамках текущей разработки.


## Python Runtime Lock

Для Ubuntu 24.04 выбран системный Python 3.12 и /usr/lib/python3.12.
Режим -B отключает создание новых bytecode caches этим процессом;
существующие .pyc учитываются в инвентаризации.

```sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
/usr/bin/python3 -B build/r800_python_runtime_lock.py \
  --mode capture --lock /local/galwear-inputs/linux-assembly-lock.json \
  --lock-sha256 "$LOCK_SHA256" --source-sha "$HEAD_SHA" \
  > /local/galwear-inputs/python-runtime-lock.json
sha256sum /local/galwear-inputs/python-runtime-lock.json
/usr/bin/python3 -B build/r800_python_runtime_lock.py \
  --mode check --lock /local/galwear-inputs/linux-assembly-lock.json \
  --lock-sha256 "$LOCK_SHA256" --source-sha "$HEAD_SHA" \
  --report /local/galwear-inputs/python-runtime-lock.json \
  --report-sha256 "$PYTHON_REPORT_SHA256"
```

Инвентаризация фиксирует относительные имена, размеры, SHA-256 обычных
файлов, включая пустые файлы и существующие caches. Для .so выполняется
статический анализ ELF-кандидатов через существующий host audit без импорта
модулей. Символьные ссылки не раскрываются автоматически; они требуют review.
site-packages и dist-packages намеренно исключены, их наличие отмечается.
Ограничения числа объектов/размеров и неоднозначные ELF-кандидаты могут
потребовать доработки на реальной Ubuntu VM.

SELECTED_PYTHON_RUNTIME_BYTES_AND_ELF_CANDIDATES_ONLY не доказывает
фактический sys.path/import resolution, отсутствие sitecustomize,
сторонних модулей, dlopen или воспроизводимость.
Отчёт диагностический, пока не gate управляемой сборки.


## Изолированное наблюдение импортов Python

Только в доверенной отдельной VM, непривилегированным пользователем.
Проба импортирует код exact-head checkout, поэтому не является sandbox
для неизвестного репозитория. Сборочные entrypoints не вызываются.

```sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
/usr/bin/python3 -B build/r800_python_import_observation.py \
  --lock /local/galwear-inputs/linux-assembly-lock.json \
  --lock-sha256 "$LOCK_SHA256" \
  --runtime /local/galwear-inputs/python-runtime-lock.json \
  --runtime-sha256 "$PYTHON_REPORT_SHA256" \
  --source-sha "$HEAD_SHA" --confirm-trusted-vm \
  > /local/galwear-inputs/python-import-observation.json
```

Дочерний Python запускается с -I -S -B, очищенным окружением и фиксированным
sys.path без site-packages, dist-packages, текущего каталога и каталога build.
Путь стандартного zip должен отсутствовать. Проектные модули разрешаются
отдельным finder только по отслеживаемым Git файлам build/*.py,
с проверкой SHA-256 и компиляцией исходного текста без чтения их .pyc.
Стандартные модули проверяются по закреплённому инвентарю runtime;
для .pyc отмечается кандидат кэша, а не доказанный факт его чтения.
Импортируются Donor Manager, Local Builder и Development Readiness.
Неизвестный origin, изменение sys.path, site/sitecustomize/usercustomize
или отсутствие обязательного модуля приводят к отказу.

ISOLATED_IMPORT_ORIGINS_MATCH_ONLY относится к этому import-only сценарию.
Не подтверждает все динамические импорты во время сборки, обычный режим
запуска Python, отсутствие сторонних пакетов в других процессах, dlopen,
или полную воспроизводимость. Отчёт пока диагностический.
