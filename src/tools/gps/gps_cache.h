/* Caller validates the fix and supplies a private same-directory temp template. */
#ifndef R800_GPS_CACHE_H
#define R800_GPS_CACHE_H
struct gps_cache {
    gps_client_mutex_t mutex;
    long long last_saved;
};
#define GPS_CACHE_INIT { GPS_CLIENT_MUTEX_INIT, 0 }

/* 1: committed, 0: throttled or stale epoch, -1: I/O failure.
 * Serialize writers, but hold the connection mutex only at publication.
 * Lock order: cache -> connection. No code may take these in reverse order. */
static int gps_cache_save(struct gps_cache *cache, struct gps_client *client,
                          gps_client_epoch epoch, int guarded,
                          const char *path, char *tmp,
                          double lat, double lon, long long utc)
{
    char buf[80];
    int fd, n, ok, result = 0;
    if (!(lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 &&
          utc > 0 && utc <= 253402300799999LL))
        return 0;
    pthread_mutex_lock(&cache->mutex);
    if (utc <= cache->last_saved || utc - cache->last_saved < 60000)
        goto done;
    n = snprintf(buf, sizeof(buf), "%.6f %.6f %lld\n", lat, lon, utc);
    if (n <= 0 || n >= (int)sizeof(buf)) {
        result = -1;
        goto done;
    }
    fd = mkstemp(tmp);
    if (fd < 0) {
        result = -1;
        goto done;
    }
    ok = write(fd, buf, n) == n && fsync(fd) == 0;
    if (close(fd) != 0)
        ok = 0;
    if (!ok) {
        result = -1;
        goto remove;
    }
    if (guarded)
        pthread_mutex_lock(&client->mutex);
    if (!guarded || (epoch != 0 && client->fd >= 0 &&
                    client->phase == GPS_ACTIVE && client->epoch == epoch)) {
        if (rename(tmp, path) == 0) {
            cache->last_saved = utc;
            result = 1;
        } else {
            result = -1;
        }
    }
    if (guarded)
        pthread_mutex_unlock(&client->mutex);
remove:
    if (result != 1)
        unlink(tmp);
done:
    pthread_mutex_unlock(&cache->mutex);
    return result;
}
#endif
