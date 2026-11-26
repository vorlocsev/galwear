#ifndef R800_GPS_STANDALONE_H
#define R800_GPS_STANDALONE_H

enum gps_run_result {
    GPS_RUN_OK = 0,
    GPS_RUN_CONFIG_FAILED,
    GPS_RUN_START_FAILED,
    GPS_RUN_STOP_FAILED,
    GPS_RUN_INTERRUPTED
};

struct gps_standalone_ops {
    void (*aid)(void);
    int (*configure)(void);
    int (*start)(void);
    unsigned int (*wait)(unsigned int);
    int (*stop)(void);
    void (*cleanup)(void);
};

/* Bounded diagnostic run, never accept atoi overflow or negative sleep. */
static inline int gps_standalone_duration(const char *s, unsigned int *out)
{
    unsigned int n = 0;
    if (!s || !*s) return 0;
    while (*s) {
        unsigned int digit;
        if (*s < '0' || *s > '9') return 0;
        digit = (unsigned int)(*s++ - '0');
        if (n > (3600U - digit) / 10U) return 0;
        n = n * 10U + digit;
    }
    if (!n) return 0;
    *out = n;
    return 1;
}

/* Caller has successfully initialized the interface. If START or STOP
 * fails, vendor engine state is unknown: do not call another vendor slot.
 * Exit the process and let the supervisor handle recovery. */
static inline enum gps_run_result gps_standalone_run(
        const struct gps_standalone_ops *ops, unsigned int seconds)
{
    unsigned int remaining;
    ops->aid();
    if (ops->configure()) {
        ops->cleanup();
        return GPS_RUN_CONFIG_FAILED;
    }
    if (ops->start()) return GPS_RUN_START_FAILED;
    remaining = ops->wait(seconds);
    if (ops->stop()) return GPS_RUN_STOP_FAILED;
    ops->cleanup();
    return remaining ? GPS_RUN_INTERRUPTED : GPS_RUN_OK;
}

#endif
