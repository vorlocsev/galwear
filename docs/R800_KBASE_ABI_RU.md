# SM-R800 KBASE ABI (NON-RELEASE)

Pinned kernel 50db73fc799f20a7120a8b5f653b16cc123d856f, drivers/gpu/arm/t72x/r28p0.
API BASE_UK_VERSION 11.13. Общий обработчик kbase_ioctl используется для
native и compat. В исходнике MEM_IMPORT передаёт phandle через
u64_to_user_ptr; UMM=2, считывается int fd по пользовательскому указателю,
используется dma_buf_get(fd). Это наблюдение по исходнику, не runtime.

CI проверяет четыре git blob SHA, компилирует оригинальный UAPI header
NDK для ARM32 и ARM64 без исполнения кода. Проверяются размеры, offsets
и семь кодов ioctl: VERSION_CHECK, SET_FLAGS, GET_GPUPROPS,
GET_DDK_VERSION, MEM_IMPORT, MEM_FREE, FENCE_VALIDATE.

MEM_IMPORT — union 24 bytes; phandle offset 8, type 16, padding 20.
Никаких ioctl не вызывается. Не проверяется совместимость донорского
userspace, фактический compat pointer, job submission, DMA-BUF,
GPU или физическое устройство. safe_to_flash=false.

## DMA attachment error path

В pinned dma-buf.c dma_buf_attach возвращает ERR_PTR при отказе. R28P0
kbase_mem_from_umm проверял только NULL. Патч заменяет проверку на
IS_ERR_OR_NULL, направляя ошибку в существующий no_attachment с dma_buf_put.
CI проверяет точные blobs, git apply --check и применение только этого
hunk к временной копии, затем выполняет host-only harness из извлечённых
строк функции. Исходный guard должен пропустить ERR_PTR; исправленный
проверяется на успехе, ошибке get, ERR_PTR/NULL attach и отказе после attach.
Это синтетические указатели и счётчики, не GPU и не kernel runtime.
