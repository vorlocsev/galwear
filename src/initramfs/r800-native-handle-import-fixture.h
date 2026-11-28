#ifndef R800_NATIVE_HANDLE_IMPORT_FIXTURE_H
#define R800_NATIVE_HANDLE_IMPORT_FIXTURE_H

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cutils/native_handle.h>

/* Test-only bounded clone. Caller owns the source; a successful import
 * owns independent CLOEXEC descriptors. No Android HAL is invoked. */
static int import_model(const native_handle_t *src, size_t bytes,
                        native_handle_t **out)
{
    if (!out || *out || !src || bytes < sizeof(*src) ||
        src->version != (int)sizeof(*src) ||
        src->numFds < 1 || src->numFds > 8 ||
        src->numInts < 0 || src->numInts > 128)
        return -EINVAL;
    size_t need = sizeof(*src) + sizeof(int) *
                  (size_t)(src->numFds + src->numInts);
    if (bytes != need) return -EINVAL;
    native_handle_t *copy = calloc(1, need);
    if (!copy) return -ENOMEM;
    copy->version = src->version;
    copy->numFds = src->numFds;
    copy->numInts = src->numInts;
    for (int i = 0; i < src->numFds; ++i) {
        int fd = fcntl(src->data[i], F_DUPFD_CLOEXEC, 0);
        if (fd < 0) {
            int error = errno;
            while (i > 0) close(copy->data[--i]);
            free(copy);
            return -error;
        }
        copy->data[i] = fd;
    }
    memcpy(copy->data + copy->numFds, src->data + src->numFds,
           sizeof(int) * (size_t)src->numInts);
    *out = copy;
    return 0;
}

static int free_model(native_handle_t **owned)
{
    if (!owned || !*owned) return -EINVAL;
    native_handle_t *h = *owned;
    *owned = NULL;
    int ret = 0;
    for (int i = 0; i < h->numFds; ++i)
        if (close(h->data[i]) && !ret) ret = -errno;
    free(h);
    return ret;
}

#endif
