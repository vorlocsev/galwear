# Этап 10 — происхождение компонентов и воспроизводимость сборки SM-R800

Все изменения выполнены **только в `vorlocsev/galwear`**, ветка `development/r800-stage10-provenance-20261124`. Исходный репозиторий, `main`, PR, релизы и реальные часы не затронуты.

## Выявленные ограничения исходного процесса

1. `mkpayload-release.sh` переносил весь каталог `android/` с рабочего устройства. Флаги `SLEEP`, `CPUIDLE_DEEP` и `OVERLAY` не исключались. Теперь они удаляются вместе с `DEV`, `STAY`, `RESET_DATA`, `gemini.tries` и `userdata.img`.
2. `mkrelease.sh` ранее не сохранял контрольные суммы входных файлов и мог использовать старый распакованный кеш combination-образов. Сейчас повторное использование кеша убрано.
3. Сборка требует сторонних закрытых бинарных образов Samsung, Google и дополнительных аппаратных зависимостей. Они не входят в этот форк. Полная сборка на GitHub Actions **не выполнялась**.
4. `mke2fs`, побайтовые изменения ext4 и TAR без нормализации времени/владельцев не гарантируют одинаковый SHA-256 результата при повторной сборке.

## Новый `installer/r800_build_provenance.py`

Перед запуском команд с root и монтирования образов скрипт проверяет:

- присутствие четырёх входов: Samsung `COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5`, `r800-boot.img`, `vendor.img`, `payload.tar`;
- состав combination TAR: необходимые загрузочные/recovery-компоненты, отсутствие `cm.bin`, CSA/EFS, абсолютных путей, дубликатов и ссылок;
- состав payload TAR: отсутствие экспериментальных флагов, личного `userdata.img`, небезопасных путей и ссылок, наличие **нулевого** 1 МиБ `android/persistent.img`;
- заголовок NZIT и структуру таблицы EXYN в boot.img, ext4 magic в vendor.img;
- SHA-256 и размер каждого входного образа, а также всех файлов под `build/`, `payload/`, `installer/` и `src/`.

Затем `mkrelease.sh` записывает начальный снимок:

```text
<work-dir>/r800-build-inputs.json
```

После формирования `R800-WearOS.tar.md5` он:

- повторно вычисляет SHA-256 входов и исходников, отклоняет изменения после preflight;
- проверяет MD5, имена 12 разрешённых образов, совпадение восьми важных компонентов с **предоставленным** reference-архивом и структуру NZIT;
- записывает файл `<release>/images/R800-WearOS.build-evidence.json` с хешами входов и результата.

Этот манифест **не является** доказательством подлинности Samsung/Google, криптографической подписи S-Boot или побайтовой воспроизводимости.

## Офлайн-проверка перед сборкой

Для уже подготовленного локального release tree:

```sh
python3 installer/r800_build_provenance.py preflight \
  --release-tree /path/to/release \
  --report /tmp/r800-build-inputs.json
```

Проверка итоговой упаковки (после сборки):

```sh
python3 installer/r800_build_provenance.py finalize \
  --release-tree /path/to/release \
  --input-manifest /tmp/r800-build-inputs.json \
  --report /tmp/r800-final-evidence.json
```

Эти команды не запускают прошивку, не монтируют диски и не связываются с часами. `build/mkrelease.sh` по-прежнему требует root для ext4/loop, поэтому не используется в CI.

## Тестирование

```sh
sh -n build/mkrelease.sh
sh -n build/mkpayload-release.sh
python3 -m unittest discover -s tests -p 'test_stage10_provenance.py' -v
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Тестовые архивы, NZIT, ext4-superblock и комбинационные бинарники полностью искусственные.

## До полной воспроизводимости ещё нужно

- Зафиксировать законные источники, версии и контрольные суммы закрытых компонентов без публикации бинарников.
- Убрать абсолютные пути разработчика из `build/build_vendor.sh`, `build/kbuild-native.sh`, `src/initramfs/build.sh`.
- Создать изолированную среду сборки с закреплёнными компилятором, dtc, util-linux, e2fsprogs и Python.
- Нормализовать TAR-метаданные и ext4-идентификаторы/время, затем выполнить два независимых билда и сравнить SHA-256.
- Проверить настоящие релизные образы и реальную PIT; получить способ восстановления загрузчика до любых аппаратных экспериментов.

**CI PASS на синтетических данных не означает готовности к установке Wear OS.**
