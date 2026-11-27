/* Bounded LTO snapshot. Caller provides trusted parent directory and fd stat adapter. */
#ifndef R800_GPS_LTO_FILE_H
#define R800_GPS_LTO_FILE_H
#define GPS_LTO_LIMIT (256U * 1024U)
static long gps_lto_fd_read(void *ctx, char *buf, unsigned int size)
{
    return read(*(int *)ctx, buf, size);
}

/* Reject non-regular, linked, writable-by-others and changed files.
 * Metadata comparison is not cryptographic or format authentication. */
static int gps_lto_file(const char *path, char *buf, unsigned int cap)
{
    struct gps_cache_meta before, after;
    int fd, n = -1;
    if (!path || !buf || !cap || cap > GPS_LTO_LIMIT)
        return -1;
    fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (gps_cache_stat(fd, &before) || (before.mode & 0170000U) != 0100000U ||
        (before.mode & 07022U) || before.links != 1 ||
        before.size <= 0 || before.size > cap)
        goto done;
    n = gps_read_lto(gps_lto_fd_read, &fd, buf, cap);
    if (n != before.size || gps_cache_stat(fd, &after) ||
        before.mode != after.mode || before.links != after.links || before.size != after.size ||
        before.mtime != after.mtime || before.mtime_ns != after.mtime_ns ||
        before.ctime != after.ctime || before.ctime_ns != after.ctime_ns)
        n = -1;
done:
    if (close(fd) != 0)
        n = -1;
    return n;
}
#endif
