/* Shared bounded reader. Platform adapter fills metadata from the opened fd. */
#ifndef R800_GPS_CACHE_READ_H
#define R800_GPS_CACHE_READ_H
struct gps_cache_meta {
    unsigned mode, links;
    long long size;
    unsigned mtime, mtime_ns, ctime, ctime_ns;
};
static int gps_cache_stat(int fd, struct gps_cache_meta *out);

static int gps_cache_meta_valid(const struct gps_cache_meta *m)
{
    return (m->mode & 0177777U) == 0100600U && m->links == 1 &&
           m->size > 0 && m->size <= 95;
}

/* Restore the watermark even for an old (non-injectable) record. A future
 * record never advances it. The caller supplies a trusted runtime directory. */
static int gps_cache_load(struct gps_cache *cache, const char *path, long long now,
                          double *lat, double *lon, long long *utc, float *acc)
{
    char buf[96];
    struct gps_cache_meta before, after;
    double x, y;
    long long t, age;
    int fd, used = 0, ok = 0;
    if (now <= 0 || now > GPS_UTC_MAX)
        return 0;
    pthread_mutex_lock(&cache->mutex);
    fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        goto done;
    if (gps_cache_stat(fd, &before) || !gps_cache_meta_valid(&before))
        goto close_file;
    while (used < (int)sizeof(buf)) {
        long n = read(fd, buf + used, sizeof(buf) - used);
        if (n < 0 || n > (long)sizeof(buf) - used)
            goto close_file;
        if (!n)
            break;
        used += (int)n;
    }
    if (used != before.size || gps_cache_stat(fd, &after) ||
        before.mode != after.mode || before.links != after.links || before.size != after.size ||
        before.mtime != after.mtime || before.mtime_ns != after.mtime_ns ||
        before.ctime != after.ctime || before.ctime_ns != after.ctime_ns)
        goto close_file;
    if (close(fd) != 0)
        goto done;
    if (buf[used-1] != '\n' || !gps_parse_seed(buf, used, &x, &y, &t) ||
        t > now || t < cache->last_saved)
        goto done;
    cache->last_saved = t;
    age = now - t;
    if (age <= 30LL * 86400000 && (x != 0 || y != 0)) {
        *lat = x; *lon = y; *utc = t;
        *acc = age < 86400000 ? 2000.0f : 25000.0f;
        ok = 1;
    }
    goto done;
close_file:
    close(fd);
done:
    pthread_mutex_unlock(&cache->mutex);
    return ok;
}
#endif
