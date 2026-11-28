# SM-R800: оценка вместимости Development Tree

Инструмент r800_review_handover.py теперь включает storage_estimate. Без измерений он показывает только размер файлов и количество новых inode. Размеры разделов p15/p17 не предполагаются. Для boot используется исторический лимит 18 MiB, а не измеренный размер раздела.

## Размещение

- p15: r800-android/vendor.img (вариант с CSC, используемый start.sh).
- p17: всё дерево r800dev, включая system.img.
- p16/p18: исключены из размещения и считаются сохраняемыми.
- vendor/ и development-boot/effective.config, init, initramfs.generated: материалы сборки; не считаются дополнительными файлами на часах. Initramfs уже встроен в Image.

Расчёт предполагает полную новую копию без удаления существующих файлов, без экономии за счёт sparse и без повторного использования существующих каталогов. Он округляет каждый файл до размера блока, добавляет один блок на каталог и явно заданный резерв. Метаданные ext4, расширенные атрибуты, журнал, изменения во время копирования и userdata/persistent полностью не моделируются.

## Необязательные данные измерения

JSON со схемой galwear-r800-capacity-observation-v1, model SM-R800, scope OPERATOR_REPORTED_READ_ONLY и partitions, содержащим ровно p15 и p17. Для каждого раздела нужны целочисленные block_size (1024, 2048 или 4096), available_blocks (доступные, а не общие или резервные блоки), available_inodes, reserve_bytes и reserve_inodes. Резерв обязателен и должен быть положительным. Не подставлять демонстрационные числа вместо измерений.

Передать файл через --capacity и его SHA-256 через --capacity-sha256 вместе с обычными параметрами handover review. Пример команды без измерений:

```sh
python3 build/r800_review_handover.py --tree /local/build/development \
  --tree-sha256 <integrated-development-evidence-sha256> \
  --source-sha <exact-commit> --output /local/handover-review.json
```

ESTIMATE_FITS_REPORTED_CAPACITY означает только прохождение расчётной модели с предоставленными данными. Оно не подтверждает подлинность наблюдения, размер физических разделов, работоспособность файловой системы или пригодность к установке. CAPACITY_NOT_MEASURED — отсутствие измерений, а не ошибка сборки. HOLD_HARDWARE_UNVERIFIED и safe_to_flash=false сохраняются во всех случаях. Инструмент не выполняет операции на устройстве.
