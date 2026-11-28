# Выделенная сборочная VM GalWearOS SM-R800 (кандидат)

Профиль: build/vm/r800-ubuntu-24.04-profile.json.
Целевой guest — Ubuntu Server 24.04 amd64, без физического доступа к часам
и дискам хоста. Рекомендованные ресурсы: 4 vCPU, 12 GiB RAM, 120 GiB
виртуального диска; минимум 40 GiB свободного рабочего места перед сборкой.
Потребность полной сборки ядра с исходниками может быть больше.
Гипервизор выбирается оператором. Этот профиль не развёртывает VM.

## 1. Создание и подготовка

- Получить официальный Ubuntu Server ISO. Проверить его SHA-256 по
  доверенному подписанному списку Canonical. Записать фактический ISO pin
  отдельно от исходного профиля; null в профиле означает неизвестный ISO.
- Создать новую VM и виртуальный диск. Отключить USB/physical disk
  passthrough, общие папки, clipboard и drag-and-drop. Для установки и
  получения зависимостей использовать NAT; перед работой с локальными
  донорскими копиями отключить виртуальную сеть.
- Установить систему с обычным непривилегированным пользователем. Root
  требуется только в отдельной синтетической mount probe и существующем
  локальном vendor builder. Не запускать наблюдение Python/glibc от root.
- Получить рабочую ветку форка vorlocsev/galwear, проверить полный SHA
  и чистый tracked checkout. Использовать отдельные канонические каталоги
  для входов, результатов, отчётов и временных файлов (см. JSON).
  Создать каталоги вручную с правами минимально необходимых пользователей.
  Не подключать оригинальные накопители; доноры доставляются отдельно в
  виде локальных копий с установленными SHA-256.

## 2. Установка пакетов

Профиль разделяет assembly (из готовых компонентов), compilation
(дополнительные инструменты для сборки компонентов) и optional_guest_tests.
Набор основан на используемых проектом CI и локальном builder. Это
список пакетов-кандидатов, не замороженный APT snapshot.

Из чистого checkout в новой VM, при включённой сети:

```sh
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
profile=build/vm/r800-ubuntu-24.04-profile.json
# assembly или compilation; guest-tests добавляет qemu-user-static/bubblewrap.
mode=assembly
/usr/bin/python3 -I -S -B - "$profile" "$mode" <<'PY' > /tmp/galwear-package-list.txt
import json, sys
p=json.load(open(sys.argv[1]))
mode=sys.argv[2]
assert mode in ("assembly","compilation","guest-tests")
groups=["assembly"]
if mode!="assembly":
    groups.append("compilation")
if mode=="guest-tests":
    groups.append("optional_guest_tests")
print("\n".join(sorted({name for group in groups for name in p["packages"][group]})))
PY
sudo apt-get update
xargs -r sudo apt-get install -y --no-install-recommends -- < /tmp/galwear-package-list.txt
rm /tmp/galwear-package-list.txt
```

Android NDK r27c и его selected tool pins — отдельный контракт.
Исходники kernel, erofs-utils и прочие внешние входы — отдельные pins.
Не устанавливать случайные pip-пакеты в системный Python.

## 3. Снимок версий пакетов

```sh
HEAD_SHA=$(git rev-parse HEAD)
/usr/bin/python3 -B build/r800_vm_package_lock.py \
  --mode capture --profile "$mode" --source-sha "$HEAD_SHA" \
  > /local/galwear-evidence/vm-package-lock.json
sha256sum /local/galwear-evidence/vm-package-lock.json
/usr/bin/python3 -B build/r800_vm_package_lock.py \
  --mode check --profile "$mode" --source-sha "$HEAD_SHA" \
  --lock /local/galwear-evidence/vm-package-lock.json \
  --lock-sha256 "$PACKAGE_LOCK_SHA256"
```

OBSERVED_PACKAGE_VERSIONS_ONLY фиксирует полную наблюдаемую таблицу
установленных package:architecture=version и SHA-256 профиля.
Отсутствие обязательных пакетов или foreign architecture требуют review.
Незавершённое состояние dpkg отклоняется. Версии не доказывают подлинность
пакетов, неизменность их файлов или байтов deb.

## 4. Приёмка чистой VM

Выполнить из R800_LINUX_ASSEMBLY_ENVIRONMENT_RU.md:
Linux Environment Lock, Host ELF Lock, Synthetic Mount Probe, glibc
Loader Observation, Python Runtime Lock, Python Import Observation,
Host Runtime Diagnostic Chain. Отдельно выполнить регрессионные тесты:

```sh
/usr/bin/python3 -B build/r800_integrated_regression.py
```

Сохранить stdout, exit codes, exact HEAD и pins отчётов. После завершения
проб выключить VM, отключить сеть и сделать baseline snapshot без доноров.
Зафиксировать версию гипервизора, параметры виртуального оборудования,
ISO pin, package lock pin и идентификатор snapshot в журнале оператора.
Для побайтового закрепления экспортированной VM потребуется отдельный
контроль всех файлов экспорта и их SHA-256.

## 5. Только затем сборка

В копии baseline VM подготовить локальный Donor Manager workspace и
выполнить managed check. Оригинальные образы отсутствуют в проекте.
Полную сборку проводить только после успешной проверки входов и VM.

Профиль и package lock пока диагностические. VM не создана, фактические
версии пакетов Ubuntu и результаты проб не получены. Никаких релизов,
установки на часы или подтверждения воспроизводимости.
safe_to_flash=false.
