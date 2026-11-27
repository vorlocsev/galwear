/* QEMU test-only EVIOCGNAME adapter. No real device ioctl forwarding. */
#include <errno.h>
#include <linux/input.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>

static const char *const names[] = {
    "accelerometer_sensor", "gyro_sensor", "pressure_sensor",
    "light_sensor", "hrm_lib_sensor", "uncal_gyro_sensor"
};

int ioctl(int fd, int request, ...)
{
    struct stat actual, wanted;
    if ((unsigned int)request != (unsigned int)EVIOCGNAME(63) ||
        fstat(fd, &actual) || !S_ISFIFO(actual.st_mode)) {
        errno = ENOTTY;
        return -1;
    }
    for (unsigned int i = 0; i < sizeof(names)/sizeof(names[0]); ++i) {
        char path[64];
        snprintf(path, sizeof(path), "/dev/input/event%u", i);
        if (lstat(path, &wanted) || !S_ISFIFO(wanted.st_mode) ||
            wanted.st_ino != actual.st_ino || wanted.st_dev != actual.st_dev)
            continue;
        va_list ap;
        va_start(ap, request);
        char *dst = va_arg(ap, char *);
        va_end(ap);
        size_t n = strlen(names[i]) + 1;
        memcpy(dst, names[i], n);
        return (int)n;
    }
    errno = ENOTTY;
    return -1;
}
