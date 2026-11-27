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
