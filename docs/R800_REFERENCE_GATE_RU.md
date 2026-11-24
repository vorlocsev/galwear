# SM-R800: обязательное офлайн-сравнение recovery перед записью

Ветка `development/r800-reference-gate-20261124` находится **только в `vorlocsev/galwear`**. Никаких новых PR, изменений `main` или действий с исходным репозиторием.

## Изменение поведения установщика

В старом интерфейсе было достаточно `--confirm-r800` и проверки `.tar.md5`, чтобы начать подключение по Odin. Анализ `sboot.bin` и recovery был отдельной утилитой, поэтому его можно было пропустить.

Теперь прямой вызов `flash_ap_package()` и обычный запуск CLI требуют **локальный reference combination-архив**. До создания сетевого сокета выполняются:

1. MD5-контроль и белый список разрешённых TAR-образов.
2. Сравнение восьми компонентов `sboot.bin`, `param.bin`, `dzImage-recovery`, `ramdisk.img`, `ramdisk-recovery.img`, `system-data.img`, `nad_refer.bin`, `nad_fw.bin` по SHA-256 с переданным reference.
3. Структурная проверка `dzImage` и `dzImage-recovery` как NZIT/EXYN.
4. После подключения устройства (не выполнялось в данном исследовании) остаётся обязательная проверка live PIT и вместимости разделов до передачи данных.

Если comparison не проходит или reference отсутствует, сетевое подключение не открывается.

## Полностью офлайн

Проверка TAR:

```sh
python3 installer/netodin.py --preflight-only --ap R800-WearOS.tar.md5
```

Проверка TAR, S-Boot и recovery без соединения с часами:

```sh
python3 installer/netodin.py --preflight-only \
  --ap R800-WearOS.tar.md5 \
  --combination-reference COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5
```

Отдельный JSON-отчёт по заранее сохранённому PIT:

```sh
python3 installer/r800_preflight_report.py \
  --package R800-WearOS.tar.md5 --pit-file SM-R800.pit \
  --combination COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5 \
  --output r800-report.json
```

## Режим записи

В коде всё ещё существует экспериментальный live-режим с явными параметрами `--confirm-r800` и `--combination-reference`. Он **НЕ прошёл аппаратных испытаний и НЕ должен использоваться на часах только на основании зелёного CI**. Возможна невосстановимая ошибка загрузчика.

Пример команды записи здесь намеренно не приводится.

### Что НЕ проверяет reference comparison

- Подлинность самого reference combination-архива Samsung.
- Совместимость с конкретной аппаратной ревизией и retail/engineering S-Boot.
- Подпись RSA или anti-rollback.
- Проводное восстановление.
- Реальные ответы NetOdin, сектора PIT и стабильность аккумулятора.

GitHub Actions выполняет только синтетические unit-тесты и имитирует Python-обмен; реальную прошивку не запускает.
