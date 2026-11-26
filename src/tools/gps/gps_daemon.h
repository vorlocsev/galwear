#ifndef R800_GPS_DAEMON_H
#define R800_GPS_DAEMON_H

enum gps_daemon_state {
    GPS_DAEMON_READY, GPS_DAEMON_ACTIVE, GPS_DAEMON_BROKEN, GPS_DAEMON_CLOSED
};

struct gps_daemon_ops {
    void (*aid)(void);
    int (*configure)(void);
    int (*start)(void);
    int (*stop)(void);
    void (*cleanup)(void);
    int (*reinit)(void);
};

/* READY means init succeeded; all operations are serialized by the server. */
static inline int gps_daemon_session(enum gps_daemon_state *state,
                                     const struct gps_daemon_ops *ops, int on)
{
    if (*state != GPS_DAEMON_READY && *state != GPS_DAEMON_ACTIVE)
        return -1;
    if (on) {
        if (*state == GPS_DAEMON_ACTIVE) return 0;
        ops->aid();
        if (ops->configure()) {
            /* Retry configuration once, before START has been called. */
            ops->cleanup();
            *state = GPS_DAEMON_BROKEN;
            if (ops->reinit()) return -1;
            *state = GPS_DAEMON_READY;
            ops->aid();
            if (ops->configure()) return -1;
        }
        if (ops->start()) {
            *state = GPS_DAEMON_BROKEN;
            return -1;
        }
        *state = GPS_DAEMON_ACTIVE;
    } else {
        if (*state == GPS_DAEMON_READY) return 0;
        if (ops->stop()) {
            *state = GPS_DAEMON_BROKEN;
            return -1;
        }
        *state = GPS_DAEMON_READY;
    }
    return 0;
}

/* No vendor calls after an ambiguous start/stop or failed reinit. */
static inline int gps_daemon_close(enum gps_daemon_state *state,
                                   const struct gps_daemon_ops *ops)
{
    if (*state == GPS_DAEMON_CLOSED) return 0;
    if (*state == GPS_DAEMON_BROKEN) return -1;
    if (gps_daemon_session(state, ops, 0)) return -1;
    ops->cleanup();
    *state = GPS_DAEMON_CLOSED;
    return 0;
}

#endif
