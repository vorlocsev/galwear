/* Read a complete bounded LTO stream; never inject a partial prefix. */
#ifndef R800_GPS_LTO_H
#define R800_GPS_LTO_H
typedef long (*gps_lto_reader)(void *, char *, unsigned int);
static int gps_read_lto(gps_lto_reader reader, void *ctx, char *buf, unsigned int cap)
{
    unsigned int n = 0;
    char extra;
    if (!reader || !buf || !cap || cap > 2147483647U)
        return -1;
    while (n < cap) {
        long k = reader(ctx, buf + n, cap - n);
        if (k < 0 || (unsigned long)k > cap - n)
            return -1;
        if (!k)
            return (int)n;
        n += (unsigned int)k;
    }
    return reader(ctx, &extra, 1) == 0 ? (int)n : -1;
}
#endif
