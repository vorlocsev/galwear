/* Shared socket ownership and serialized callback writes. Caller provides
 * gps_client_mutex_t, GPS_CLIENT_MUTEX_INIT and POSIX socket declarations. */
#ifndef R800_GPS_CLIENT_H
#define R800_GPS_CLIENT_H
struct gps_client {
    gps_client_mutex_t mutex;
    int fd;
};
#define GPS_CLIENT_INIT { GPS_CLIENT_MUTEX_INIT, -1 }

/* The single serve loop owns close(); callback writers never close a fd. */
static int gps_client_attach(struct gps_client *c, int fd)
{
    int ok;
    pthread_mutex_lock(&c->mutex);
    ok = fd >= 0 && c->fd == -1;
    if (ok)
        c->fd = fd;
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
    if (c->fd == fd)
        c->fd = -1;
    pthread_mutex_unlock(&c->mutex);
}

static void gps_client_send(struct gps_client *c, const char *line, int len)
{
    pthread_mutex_lock(&c->mutex);
    if (c->fd >= 0 && len > 0 &&
        send(c->fd, line, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL) != len) {
        /* A partial frame or failed send invalidates the entire connection. */
        shutdown(c->fd, SHUT_RDWR);
        c->fd = -1;
    }
    pthread_mutex_unlock(&c->mutex);
}
#endif
