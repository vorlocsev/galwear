/* Wire framing and cached-position validation; no libc dependency. */
#ifndef R800_GPS_OUTPUT_H
#define R800_GPS_OUTPUT_H
#include "gps_command.h"
static int gps_valid_seed(double lat, double lon, long long utc)
{
    return lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 &&
           utc > 0 && utc <= GPS_UTC_MAX;
}
/* The 30-day age ceiling fits uint32_t but exceeds signed int32.
 * Narrow only after validation; avoid ARM's 64-bit division helper in
 * the freestanding bridge (no compiler runtime linked). */
static inline int gps_seed_age(long long now, long long utc,
                              unsigned int *minutes, unsigned int *accuracy)
{
    if (utc <= 0 || now < utc || now > GPS_UTC_MAX ||
        now - utc > 2592000000LL)
        return 0;
    unsigned int age = (unsigned int)(now - utc);
    *minutes = age / 60000U;
    *accuracy = age < 86400000U ? 2000U : 25000U;
    return 1;
}
/* Caller provides len + 1 bytes of writable storage. */
static int gps_parse_seed(char *buf, int len, double *lat, double *lon, long long *utc)
{
    const char *p;
    double x, y;
    long long t;
    if (!buf || len <= 0 || len > 95) return 0;
    for (int i = 0; i < len; ++i)
        if (!buf[i]) return 0;
    if (buf[len-1] == '\n') --len;
    if (len && buf[len-1] == '\r') --len;
    buf[len] = 0;
    p = gps_space(buf);
    if (!gps_decimal(&p, &x)) return 0;
    p = gps_space(p);
    if (!gps_decimal(&p, &y)) return 0;
    p = gps_space(p);
    if (!gps_uint(&p, GPS_UTC_MAX, &t) || *gps_space(p)) return 0;
    if (!gps_valid_seed(x, y, t)) return 0;
    *lat = x; *lon = y; *utc = t;
    return 1;
}
/* Keep the original sentence intact. Only strip terminal CR/LF.
 * No checksum or receiver-specific semantics are asserted. */
static int gps_nmea_length(const char *buf, int len)
{
    if (!buf || len <= 0 || len > 252) return -1;
    while (len && (buf[len-1] == '\r' || buf[len-1] == '\n')) --len;
    if (len <= 0 || len > 250 || (buf[0] != '$' && buf[0] != '!')) return -1;
    for (int i = 0; i < len; ++i)
        if ((unsigned char)buf[i] < 32 || (unsigned char)buf[i] > 126) return -1;
    return len;
}
#endif
