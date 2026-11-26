/* Native shared reader tests; no Tizen execution. */
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

typedef pthread_mutex_t gps_client_mutex_t;
#define GPS_CLIENT_MUTEX_INIT PTHREAD_MUTEX_INITIALIZER
#include "gps_client.h"
#include "gps_cache.h"
#include "gps_output.h"
#include "gps_cache_read.h"

static int change_metadata, stat_calls;
static int gps_cache_stat(int fd, struct gps_cache_meta *out)
{
    struct stat s;
    if (fstat(fd, &s)) return -1;
    *out = (struct gps_cache_meta){s.st_mode, s.st_nlink, s.st_size,
        s.st_mtim.tv_sec, s.st_mtim.tv_nsec, s.st_ctim.tv_sec, s.st_ctim.tv_nsec};
    if (change_metadata && ++stat_calls == 2) ++out->ctime_ns;
    return 0;
}
static struct gps_cache cache = GPS_CACHE_INIT;
static struct gps_client client = GPS_CLIENT_INIT;
static const long long base = 1700000000000LL;
static char dir[] = "/tmp/r800-cache-read-XXXXXX", path[128], other[128];
static double lat, lon;
static long long utc;
static float acc;
static int load(long long now)
{
    return gps_cache_load(&cache, path, now, &lat, &lon, &utc, &acc);
}
static void replace(const char *text, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    assert(fd >= 0 && write(fd, text, len) == (ssize_t)len && close(fd) == 0);
}
static void record(const char *xy, long long t)
{
    char buf[96];
    int n = snprintf(buf, sizeof(buf), "%s %lld\n", xy, t);
    assert(n > 0 && n < (int)sizeof(buf));
    replace(buf, n);
}
int main(void)
{
    assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/gps.last", dir);
    snprintf(other, sizeof(other), "%s/other", dir);
    assert(!load(base));
    record("12.500000 -34.250000", base);
    assert(load(base) && lat == 12.5 && lon == -34.25 && utc == base && acc == 2000);
    assert(cache.last_saved == base);
    char tmp[160];
    snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path);
    assert(gps_cache_save(&cache, &client, 0, 0, path, tmp, 1, 2, base-1) == 0);
    assert(gps_cache_save(&cache, &client, 0, 0, path, tmp, 1, 2, base+59999) == 0);
    puts("RESTART_WATERMARK=PASS");
    assert(load(base+86400000) && acc == 25000);
    assert(load(base+30LL*86400000));
    assert(!load(base+30LL*86400000+1) && cache.last_saved == base);
    record("1 2", base+120000);
    assert(!load(base+1) && cache.last_saved == base);
    record("0 0", base+60000);
    assert(!load(base+60000) && cache.last_saved == base+60000);
    puts("AGE_FUTURE_AND_ZERO=PASS");
    record("12.5 -34.25", base);
    assert(!load(base+60000) && cache.last_saved == base+60000);
    const char *bad[] = {"", "91 1 1700000120000\n", "1 2 1700000120000", "1 2 1700000120000\nmore\n"};
    for (unsigned i=0; i<sizeof(bad)/sizeof(bad[0]); ++i) {
        replace(bad[i], strlen(bad[i]));
        assert(!load(base+180000));
    }
    char oversized[96]; memset(oversized, '1', sizeof(oversized));
    replace(oversized, sizeof(oversized)); assert(!load(base+180000));
    replace("1 2\0 1700000120000\n", 20); assert(!load(base+180000));
    assert(cache.last_saved == base+60000);
    puts("MALFORMED_AND_REGRESSION=PASS");
    record("1 2", base+120000);
    assert(chmod(path,0644)==0 && !load(base+180000));
    assert(chmod(path,0600)==0 && link(path,other)==0 && !load(base+180000));
    assert(unlink(other)==0 && rename(path,other)==0);
    assert(symlink(other,path)==0 && !load(base+180000));
    assert(unlink(path)==0 && mkfifo(path,0600)==0 && !load(base+180000));
    assert(unlink(path)==0 && mkdir(path,0700)==0 && !load(base+180000));
    assert(rmdir(path)==0 && rename(other,path)==0);
    puts("FILE_TYPE_LINKS_AND_MODE=PASS");
    change_metadata=1; stat_calls=0;
    assert(!load(base+180000) && cache.last_saved == base+60000);
    change_metadata=0;
    assert(load(base+180000) && cache.last_saved == base+120000);
    puts("METADATA_CHANGE=PASS");
    assert(unlink(path)==0 && rmdir(dir)==0);
    return 0;
}
