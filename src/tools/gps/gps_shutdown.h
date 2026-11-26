#ifndef R800_GPS_SHUTDOWN_H
#define R800_GPS_SHUTDOWN_H

#ifdef R800_GPS_BRIDGE_HOST_TEST
#include <poll.h>
#include <signal.h>
#include <errno.h>
#define GPS_WAIT_ERRNO errno
#else
struct pollfd { int fd; short events, revents; };
int poll(struct pollfd *, unsigned long, int);
void (*signal(int, void (*)(int)))(int);
int *__errno_location(void);
#define GPS_WAIT_ERRNO (*__errno_location())
#define SIGTERM 15
#define SIGINT 2
#define SIG_ERR ((void (*)(int))-1)
#define POLLIN 1
#define EINTR 4
#endif

/* A signal can be delivered to any vendor thread. Only a lock-free
 * atomic store is performed there; the owner loop performs cleanup. */
_Static_assert(__atomic_always_lock_free(sizeof(int), 0), "signal flag must be lock free");
static int gps_shutdown_requested;
static void gps_shutdown_handler(int sig)
{
    (void)sig;
    __atomic_store_n(&gps_shutdown_requested, 1, __ATOMIC_RELAXED);
}
static int gps_shutdown_pending(void)
{
    return __atomic_load_n(&gps_shutdown_requested, __ATOMIC_RELAXED);
}
static int gps_shutdown_install(void)
{
    return signal(SIGTERM, gps_shutdown_handler) != SIG_ERR &&
           signal(SIGINT, gps_shutdown_handler) != SIG_ERR ? 0 : -1;
}

/* 1 = readiness (including hangup/error), 0 = shutdown, -1 = poll error.
 * A finite timeout also handles delivery to a different thread. */
static int gps_wait_readable(int fd)
{
    struct pollfd p = {fd, POLLIN, 0};
    while (!gps_shutdown_pending()) {
        int rc = poll(&p, 1, 200);
        if (gps_shutdown_pending()) return 0;
        if (rc > 0) return 1;
        if (rc < 0 && GPS_WAIT_ERRNO != EINTR) return -1;
    }
    return 0;
}

#endif
