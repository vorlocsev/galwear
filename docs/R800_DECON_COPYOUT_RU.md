# SM-R800 — DECON ioctl copyout transaction (NON-RELEASE)

Патч ядра на базе 50db73fc799f20a7120a8b5f653b16cc123d856f
разделяет резервирование, отмену и установку release FD.
Обычный путь: подготовка кадра -> reserve -> copy_to_user ->
worker fence reference -> install release/retire -> enqueue.
На EFAULT, включая частичную запись, отменяются только резервирования,
освобождаются file reference и подготовленные DMA buffers через
существующий err_prepare; кадр не ставится в очередь.
Off-state: copyout до signal/install, на EFAULT резерв отменяется.
Выходные поля retire/release инициализируются -1 независимо от
входных данных. После передачи последней file reference sync_file
больше не разыменовывается. Изменена сигнатура внутреннего
decon_set_win_config, удалён поздний copyout из ioctl switch.

Проверены исходные строки и счётчики 14 hunks decon.h,
decon_core.c и fence.c по exact pinned source — расхождений нет.
Два дополнительных теста: отмена reserve для разных наборов окон
на simulated copyout failure и статическая проверка порядка
copyout/install/enqueue. Это host-stub/структурные тесты, не
fault injection работающего ядра. Интеграционный CI обновлён,
успешная компиляция и результаты тестов пока не подтверждены.

Ограничения: copy_to_user под decon->lock может задержать другие
операции при page fault; latency и lock ordering требуют проверки.
Частично записанные номера FD на EFAULT не являются действительными
и не должны использоваться клиентом. Предшествующая подготовка
может иметь другие побочные эффекты, полный аппаратный rollback
не доказан. Kernel runtime, sync_file и donor HWC2On1Adapter не
проверены. safe_to_flash=false, без firmware, PR, main/upstream.
