#ifndef R800_GPS_PROTOCOL_V2_H
#define R800_GPS_PROTOCOL_V2_H

/* Connection-local, nonzero, monotonically increasing 32-bit session IDs.
 * A new connection resets the sequence. No wrap or implicit downgrade. */
#define GPS_V2_MAX_ID 4294967295U
#define GPS_V2_HELLO "HELLO 2"
#define GPS_V2_READY "READY 2"

enum gps_v2_kind { GPS_V2_INVALID, GPS_V2_START, GPS_V2_STOP,
                   GPS_V2_ACK_START, GPS_V2_ACK_STOP, GPS_V2_DATA };
struct gps_v2_message {
    enum gps_v2_kind kind;
    unsigned int id;
    const char *payload;
};

static inline int gps_v2_literal(const char **p, const char *word)
{
    const char *s = *p;
    while (*word) if (*s++ != *word++) return 0;
    *p = s;
    return 1;
}

static inline int gps_v2_id(const char **p, unsigned int *out)
{
    const char *s = *p;
    unsigned int n = 0;
    if (*s < '1' || *s > '9') return 0;
    do {
        unsigned int digit = (unsigned int)(*s++ - '0');
        if (n > (GPS_V2_MAX_ID - digit) / 10U) return 0;
        n = n * 10U + digit;
    } while (*s >= '0' && *s <= '9');
    if (*s && *s != ' ') return 0;
    *p = s;
    *out = n;
    return 1;
}

/* Input is a complete bounded NUL-terminated line, without newline. */
static inline int gps_v2_parse(const char *s, struct gps_v2_message *out)
{
    struct gps_v2_message m = {GPS_V2_INVALID, 0, 0};
    const char *p = s;
    if (gps_v2_literal(&p, "START ")) m.kind = GPS_V2_START;
    else if (gps_v2_literal(&p, "STOP ")) m.kind = GPS_V2_STOP;
    else if (gps_v2_literal(&p, "ACK START ")) m.kind = GPS_V2_ACK_START;
    else if (gps_v2_literal(&p, "ACK STOP ")) m.kind = GPS_V2_ACK_STOP;
    else if (gps_v2_literal(&p, "DATA ")) m.kind = GPS_V2_DATA;
    else return 0;
    if (!gps_v2_id(&p, &m.id)) return 0;
    if (m.kind == GPS_V2_DATA) {
        const char *body;
        if (*p++ != ' ') return 0;
        m.payload = body = p;
        if (!(gps_v2_literal(&p, "FIX ") || gps_v2_literal(&p, "NMEA ") ||
              gps_v2_literal(&p, "STATUS ")) || !*p || p == body) return 0;
    } else if (*p) return 0;
    *out = m;
    return 1;
}

enum gps_v2_phase { GPS_V2_IDLE, GPS_V2_START_PENDING, GPS_V2_ACTIVE,
                    GPS_V2_STOP_PENDING };
struct gps_v2_client { enum gps_v2_phase phase; unsigned int id; };

/* Call only after READY 2. A failed send/invalid ACK requires disconnect. */
static inline int gps_v2_request(struct gps_v2_client *c, int on)
{
    if (on) {
        if (c->phase != GPS_V2_IDLE || c->id == GPS_V2_MAX_ID) return 0;
        ++c->id;
        c->phase = GPS_V2_START_PENDING;
    } else {
        if (c->phase != GPS_V2_ACTIVE) return 0;
        c->phase = GPS_V2_STOP_PENDING;
    }
    return 1;
}

/* 1 = accepted ACK, 2 = deliver data, 0 = stale data, -1 = protocol error. */
static inline int gps_v2_receive(struct gps_v2_client *c, const struct gps_v2_message *m)
{
    if (m->kind == GPS_V2_DATA) {
        if (m->id > c->id) return -1;
        return c->phase == GPS_V2_ACTIVE && m->id == c->id ? 2 : 0;
    }
    if (m->id != c->id) return -1;
    if (m->kind == GPS_V2_ACK_START && c->phase == GPS_V2_START_PENDING)
        c->phase = GPS_V2_ACTIVE;
    else if (m->kind == GPS_V2_ACK_STOP && c->phase == GPS_V2_STOP_PENDING)
        c->phase = GPS_V2_IDLE;
    else return -1;
    return 1;
}
#endif
