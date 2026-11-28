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

Следующие работы: безопасная отдельная проверка mount namespace и xattrs
на синтетическом образе, привязка environment lock к Donor Manager,
проверка динамических библиотек и закрепление версии сборочной VM.
Текущий lock не является обязательным gate существующего сборщика и не
доказывает побайтовую воспроизводимость.

NON-RELEASE. safe_to_flash=false.
