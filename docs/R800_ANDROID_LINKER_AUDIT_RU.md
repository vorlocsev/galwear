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

### Инвентарь групп EGL

Поле `graphics_inventory.egl_driver_groups` (в отдельном профиле —
`inventory.egl_driver_groups`) группирует библиотеки из `lib/egl` или
`lib64/egl` по каталогу и суффиксу для ABI SurfaceFlinger. Различаются
combined libGLES и split EGL/GLESv2, GLESv1 отмечается отдельно.
Системные EGL/GLES wrappers вне каталога egl не считаются драйверами.
Учитываются только наблюдаемые значения persist.graphics.egl,
ro.hardware.egl, ro.board.platform из ограниченного списка prop-файлов.
Конфликты, несколько групп и несовпадение явного суффикса требуют review.
Порядок загрузки свойств, runtime override, ANGLE и updated drivers не
моделируются. `selected_driver` всегда null, runtime не проверен.

### Mali / KBASE

`mali_evidence` сравнивает выбранный ABI SurfaceFlinger, имена libMali,
точный переданный kernel config и GPU-узлы DTB с существующим рецептом
R800 (CONFIG_MALI_T72X, MIDGARD, R28P0). Учитываются отключённые предки
DT-узлов, параметры ресурсов, ION, IOMMU, SYNC_FILE, DMA_SHARED_BUFFER
и ARM32 COMPAT для ARM64. Отсутствие точного config/DTB или однозначного
GPU-узла требует review; это консервативный фильтр рецепта, а не общая
проверка всех допустимых конфигураций Mali. Версия userspace, KBASE ioctl,
compat ioctl, импорт dma-buf и аппаратный GPU остаются NOT_TESTED.

## Минимальный набор graphics entrypoints

Инвентаризация дополнена проверкой непосредственно определённых экспортов
EGL/GLES2/GLES1 (минимальный диагностический набор, не полная спецификация)
и HMI (STT_OBJECT) у legacy HAL в /hw. Скрытые версии, неподходящий тип,
неизвестная таблица символов и STT_NOTYPE дают review, а не подтверждение
функции. Combined и split driver groups проверяются отдельно. Специализированный
--graphics-dependencies теперь требует также положительный статический
entrypoint gate; общий inventory сохраняет прежний статус. Отсутствующий
прямой экспорт может разрешаться через зависимости или eglGetProcAddress;
REVIEW_REQUIRED не означает доказанную несовместимость. Ни dlsym, ни
EGL init, ни KBASE runtime не выполняются. Donor archive отсутствует.

## ARM32 synthetic EGL link probe

Изолированный Bionic/QEMU с hash-pinned reference runtime проверяет split,
combined, неполный экспорт glUseProgram, отказ загрузки private library
по имени и абсолютному пути, восстановление и стабильность FD после
warmup. Библиотеки синтетические, с NDK EGL/GLES prototypes, но функции
не вызываются. Никаких реальных EGL init, GPU, SurfaceFlinger или donor
библиотек. CI публикует только JSON evidence, safe_to_flash=false.
