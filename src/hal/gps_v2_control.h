#ifndef R800_GPS_V2_CONTROL_H
#define R800_GPS_V2_CONTROL_H
#include "../tools/gps/gps_protocol_v2.h"

#define GPS_V2_TIMEOUT_MS 5000LL
struct gps_v2_control {
    struct gps_v2_client session;
    unsigned long epoch;
    long long deadline;
    int ready;
};

static inline void gps_v2_control_reset(struct gps_v2_control *c, long long now)
{
    *c = (struct gps_v2_control){0};
    c->deadline = now + GPS_V2_TIMEOUT_MS;
}

/* -1: reconnect, 0: no command, 1: START, 2: STOP.
 * The caller serializes state changes and disconnects on send failure. */
static inline int gps_v2_control_plan(struct gps_v2_control *c, int wanted,
                                      unsigned long epoch, long long now)
{
    if (now < 0 || (c->deadline && now >= c->deadline)) return -1;
    if (!c->ready || c->session.phase == GPS_V2_START_PENDING ||
        c->session.phase == GPS_V2_STOP_PENDING) return 0;
    if (c->session.phase == GPS_V2_ACTIVE && (!wanted || c->epoch != epoch)) {
        if (!gps_v2_request(&c->session, 0)) return -1;
        c->deadline = now + GPS_V2_TIMEOUT_MS;
        return 2;
    }
    if (c->session.phase == GPS_V2_IDLE && wanted) {
        if (!gps_v2_request(&c->session, 1)) return -1;
        c->epoch = epoch;
        c->deadline = now + GPS_V2_TIMEOUT_MS;
        return 1;
    }
    return 0;
}

/* Returns the shared receive result. READY is an accepted control frame.
 * Only current requested-session data may reach framework callbacks. */
static inline int gps_v2_control_receive(struct gps_v2_control *c, const char *line,
        int wanted, unsigned long epoch, long long now, const char **payload)
{
    struct gps_v2_message m;
    *payload = 0;
    if (now < 0 || (c->deadline && now >= c->deadline)) return -1;
    if (!c->ready) {
        const char *p = line;
        if (!gps_v2_literal(&p, GPS_V2_READY) || *p) return -1;
        c->ready = 1;
        c->deadline = 0;
        return 1;
    }
    if (!gps_v2_parse(line, &m)) return -1;
    int rc = gps_v2_receive(&c->session, &m);
    if (rc == 1) c->deadline = 0;
    if (rc == 2) {
        if (!wanted || c->epoch != epoch) return 0;
        *payload = m.payload;
    }
    return rc;
}
#endif
