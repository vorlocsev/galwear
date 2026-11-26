/* Shared socket ownership and serialized callback writes. Caller provides
 * gps_client_mutex_t, GPS_CLIENT_MUTEX_INIT and POSIX socket declarations. */
#ifndef R800_GPS_CLIENT_H
#define R800_GPS_CLIENT_H
typedef unsigned long long gps_client_epoch;
enum { GPS_IDLE, GPS_ACTIVE, GPS_STOPPING };
struct gps_client {
    gps_client_mutex_t mutex;
    int fd;
    gps_client_epoch epoch;
    int phase;
};
#define GPS_CLIENT_INIT { GPS_CLIENT_MUTEX_INIT, -1, 0, GPS_IDLE }

/* The single serve loop owns close(); callback writers never close a fd. */
static int gps_client_attach(struct gps_client *c, int fd)
{
    int ok;
    pthread_mutex_lock(&c->mutex);
    ok = fd >= 0 && c->fd == -1;
    if (ok) {
        c->fd = fd;
        c->phase = GPS_IDLE;
    }
    pthread_mutex_unlock(&c->mutex);
    return ok;
}

static int gps_client_matches(struct gps_client *c, int fd)
{
    int matches;
    pthread_mutex_lock(&c->mutex);
    matches = fd >= 0 && c->fd == fd;
    pthread_mutex_unlock(&c->mutex);
    return matches;
}

static void gps_client_detach(struct gps_client *c, int fd)
{
    pthread_mutex_lock(&c->mutex);
    if (c->fd == fd) {
        c->fd = -1;
        c->phase = GPS_IDLE;
    }
    pthread_mutex_unlock(&c->mutex);
}

/* A ticket identifies the wire phase at callback entry, not its HAL origin. */
static int gps_client_begin(struct gps_client *c)
{
    int ok;
    pthread_mutex_lock(&c->mutex);
    ok = c->fd >= 0 && c->phase == GPS_IDLE && c->epoch != ~0ULL;
    if (ok) {
        ++c->epoch;
        c->phase = GPS_ACTIVE;
    }
    pthread_mutex_unlock(&c->mutex);
    return ok;
}

static void gps_client_stopping(struct gps_client *c)
{
    pthread_mutex_lock(&c->mutex);
    if (c->phase == GPS_ACTIVE && c->epoch != ~0ULL) {
        ++c->epoch;
        c->phase = GPS_STOPPING;
    } else {
        c->phase = GPS_IDLE;
    }
    pthread_mutex_unlock(&c->mutex);
}

static void gps_client_end(struct gps_client *c)
{
    pthread_mutex_lock(&c->mutex);
    c->phase = GPS_IDLE;
    pthread_mutex_unlock(&c->mutex);
}

static gps_client_epoch gps_client_ticket(struct gps_client *c, int status)
{
    gps_client_epoch epoch = 0;
    pthread_mutex_lock(&c->mutex);
    if (c->fd >= 0 && (c->phase == GPS_ACTIVE || (status && c->phase == GPS_STOPPING)))
        epoch = c->epoch;
    pthread_mutex_unlock(&c->mutex);
    return epoch;
}

static void gps_client_send(struct gps_client *c, gps_client_epoch epoch, const char *line, int len)
{
    pthread_mutex_lock(&c->mutex);
    if (c->fd >= 0 && c->phase != GPS_IDLE && epoch != 0 && epoch == c->epoch && len > 0 &&
        send(c->fd, line, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL) != len) {
        /* A partial frame or failed send invalidates the entire connection. */
        shutdown(c->fd, SHUT_RDWR);
        c->fd = -1;
        c->phase = GPS_IDLE;
    }
    pthread_mutex_unlock(&c->mutex);
}
#endif
