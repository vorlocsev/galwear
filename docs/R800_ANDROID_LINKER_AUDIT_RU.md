# SM-R800 — офлайн-аудит Android ELF/Bionic/APEX

Этап не меняет Android-образы, загрузчик, main или реальные часы.
Основа — Android 11 system-as-root и смешанные ARM32/AArch64 ABI
исторического порта. Реальные донорские образы не входят в CI.

## Использование

На заранее извлечённом, неизменяемом дереве Android (system и vendor
в своих гостевых каталогах; APEX при наличии отдельно извлечён):

```sh
python3 build/r800_android_userspace_preflight.py \
  --root /path/to/android-root --config src/kernel/r800.config \
  --output /tmp/r800-structure.json
python3 build/r800_android_linker_audit.py \
  --root /path/to/android-root --output /tmp/r800-linker.json
```

Не запускать ldd, chroot или ELF из неизвестного образа. Скрипты не
монтируют, не извлекают архивы и не исполняют гостевые файлы.
Дерево должно быть доверенно подготовлено и не меняться параллельно.

## Что доказывает отчёт

- ELF32 ARM и ELF64 AArch64, DT_NEEDED из PT_DYNAMIC, проверка границ.
- Транзитивный граф библиотек с ограничением числа проверяемых объектов.
- Кандидаты из system/vendor/product/odm/system_ext и известных
  распакованных runtime/art APEX, включая Bionic.
- Отсутствующие кандидаты, несовпадающие ABI, неоднозначные имена.
- Абсолютные гостевые symlink интерпретируются внутри гостевого корня.

CANDIDATES_FOUND_ONLY не означает, что Android linker реально
разрешит все зависимости. RPATH/RUNPATH только отмечаются. Не
анализируются правила linkerconfig/VNDK, экспорт символов и их версии,
активация и подпись APEX, dlopen, VINTF, SELinux или runtime Binder.
Отсутствие распакованного APEX не доказывает его отсутствие в образе.
Не все APEX и пути библиотек включены в эвристику.

## Следующий этап

Проверить CI synthetic ELF, затем получить локальный отчёт о реальном
донорском дереве и построить проверку VINTF/HAL. Не публиковать
проприетарные образы и не переходить к аппаратной прошивке.

`safe_to_flash=false` при любом результате.

## Отдельный аудит графических зависимостей

```sh
python3 build/r800_android_linker_audit.py --root /path/to/android-root \
  --graphics-dependencies --output /tmp/r800-graphics-deps.json
```

В отличие от стандартных корней init, профиль включает обнаруженные EGL,
GLES, Mali, gralloc, hwcomposer и graphics HAL ELF, а также исполняемые
файлы графических сервисов. Инвентарь фиксирует SHA-256, ABI, SONAME,
DT_NEEDED и сведения о версиях символов. Транзитивный граф использует
существующие проверки ELF, версий, кандидатов символов и relocation.
Отсутствующие/неоднозначные зависимости и неисследованные таблицы символов
требуют REVIEW_REQUIRED. Поиск кандидатов использует общие каталоги ABI,
не моделирует EGL dlopen или реальные правила выбора драйвера; даже
STATIC_GRAPHICS_DEPENDENCY_CANDIDATES_ONLY не доказывает runtime.
Синтетический CI не содержит реальных донорских образов.
