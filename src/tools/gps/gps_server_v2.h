#ifndef R800_GPS_SERVER_V2_H
#define R800_GPS_SERVER_V2_H
#include "gps_protocol_v2.h"

enum gps_server_mode { GPS_SERVER_UNDECIDED, GPS_SERVER_V1, GPS_SERVER_V2 };
struct gps_v2_server {
    enum gps_server_mode mode;
    unsigned int id;
    int active;
};
enum gps_server_action {
    GPS_SERVER_REJECT, GPS_SERVER_READY, GPS_SERVER_START, GPS_SERVER_STOP,
    GPS_SERVER_TIME, GPS_SERVER_LOC, GPS_SERVER_NOOP
};

static inline int gps_server_equal(const char *s, const char *literal)
{
    return gps_v2_literal(&s, literal) && !*s;
}

/* Owner thread only. Call commit only after vendor success. */
static inline enum gps_server_action gps_server_plan(
        struct gps_v2_server *s, const char *line, unsigned int *id)
{
    struct gps_v2_message m;
    const char *p = line;
    *id = 0;
    if (s->mode == GPS_SERVER_UNDECIDED && gps_server_equal(line, GPS_V2_HELLO)) {
        s->mode = GPS_SERVER_V2;
        return GPS_SERVER_READY;
    }
    if (s->mode != GPS_SERVER_V2) {
        if (gps_server_equal(line, "START")) {
            s->mode = GPS_SERVER_V1;
            return s->active ? GPS_SERVER_NOOP : GPS_SERVER_START;
        }
        if (gps_server_equal(line, "STOP")) {
            s->mode = GPS_SERVER_V1;
            return s->active ? GPS_SERVER_STOP : GPS_SERVER_NOOP;
        }
    }
    if (gps_v2_literal(&p, "TIME ")) {
        if (!*p) return GPS_SERVER_REJECT;
        if (s->mode == GPS_SERVER_UNDECIDED) s->mode = GPS_SERVER_V1;
        return GPS_SERVER_TIME;
    }
    p = line;
    if (gps_v2_literal(&p, "LOC ")) {
        if (!*p) return GPS_SERVER_REJECT;
        if (s->mode == GPS_SERVER_UNDECIDED) s->mode = GPS_SERVER_V1;
        return GPS_SERVER_LOC;
    }
    if (s->mode != GPS_SERVER_V2 || !gps_v2_parse(line, &m))
        return GPS_SERVER_REJECT;
    if (m.kind == GPS_V2_START && !s->active && s->id != GPS_V2_MAX_ID &&
        m.id == s->id + 1U) {
        *id = m.id;
        return GPS_SERVER_START;
    }
    if (m.kind == GPS_V2_STOP && s->active && m.id == s->id) {
        *id = m.id;
        return GPS_SERVER_STOP;
    }
    return GPS_SERVER_REJECT;
}

static inline void gps_server_commit(struct gps_v2_server *s,
        enum gps_server_action action, unsigned int id)
{
    if (action == GPS_SERVER_START) {
        s->id = id;
        s->active = 1;
    } else if (action == GPS_SERVER_STOP) {
        s->active = 0;
    }
}
#endif
