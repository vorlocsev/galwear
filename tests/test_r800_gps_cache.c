/* Native tests of the exact cache writer shared with GPS Bridge. */
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

typedef pthread_mutex_t gps_client_mutex_t;
#define GPS_CLIENT_MUTEX_INIT PTHREAD_MUTEX_INITIALIZER
#include "gps_client.h"

static pthread_barrier_t staged;
static int pause_sync, fail_sync;
static void sync_barrier(void)
{
    int r = pthread_barrier_wait(&staged);
    assert(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
}
static int test_fsync(int fd)
{
    if (pause_sync) {
        sync_barrier();
        sync_barrier();
    }
    if (fail_sync) { errno = EIO; return -1; }
    return fsync(fd);
}
#define fsync test_fsync
#include "gps_cache.h"
#undef fsync

static struct gps_client client = GPS_CLIENT_INIT;
static struct gps_cache cache = GPS_CACHE_INIT;
static char dir[] = "/tmp/r800-cache-XXXXXX", path[128];
static const long long base = 1700000000000LL;

static int save(gps_client_epoch epoch, int guarded, long long utc)
{
    char tmp[160];
    assert(snprintf(tmp, sizeof(tmp), "%s.XXXXXX", path) > 0);
    return gps_cache_save(&cache, &client, epoch, guarded, path, tmp, 12.5, -34.25, utc);
}
static void check_file(long long utc)
{
    struct stat st;
    char buf[80], expected[80];
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    assert(fd >= 0 && fstat(fd, &st) == 0 && (st.st_mode & 0777) == 0600);
    int n = (int)read(fd, buf, sizeof(buf));
    int size = snprintf(expected, sizeof(expected), "12.500000 -34.250000 %lld\n", utc);
    assert(n == size && memcmp(buf, expected, size) == 0);
    assert(close(fd) == 0);
}
static void no_temps(void)
{
    DIR *d = opendir(dir);
    assert(d);
    struct dirent *entry;
    while ((entry = readdir(d)))
        assert(!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") || !strcmp(entry->d_name, "gps.last"));
    closedir(d);
}
static void *old_writer(void *arg)
{
    gps_client_epoch epoch = *(gps_client_epoch *)arg;
    assert(save(epoch, 1, base+180000) == 0);
    return NULL;
}
static atomic_int reader_done;
static void *reader(void *arg)
{
    (void)arg;
    while (!atomic_load(&reader_done)) {
        char buf[80], extra;
        long long utc;
        double lat, lon;
        int fd = open(path, O_RDONLY | O_NOFOLLOW);
        assert(fd >= 0);
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        assert(n > 0 && n < (ssize_t)sizeof(buf)-1 && buf[n-1] == '\n');
        buf[n] = 0;
        assert(sscanf(buf, "%lf %lf %lld %c", &lat, &lon, &utc, &extra) == 3);
        assert(lat == 12.5 && lon == -34.25 && utc >= base);
        assert(close(fd) == 0);
    }
    return NULL;
}
int main(void)
{
    int f[2];
    pthread_t worker;
    assert(mkdtemp(dir));
    assert(snprintf(path, sizeof(path), "%s/gps.last", dir) > 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0);
    assert(gps_client_attach(&client, f[0]) && gps_client_matches(&client, f[0]));
    assert(gps_client_begin(&client));
    gps_client_epoch first = gps_client_ticket(&client, 0);
    assert(save(first, 1, base) == 1);
    check_file(base);
    assert(save(first, 1, base-1) == 0 && save(first, 1, base+59999) == 0);
    assert(save(first, 1, base+60000) == 1);
    check_file(base+60000); no_temps(); puts("MONOTONIC_THROTTLE=PASS");
    fail_sync = 1;
    assert(save(first, 1, base+120000) == -1);
    fail_sync = 0;
    check_file(base+60000); no_temps();
    assert(save(first, 1, base+120000) == 1);
    check_file(base+120000); puts("SYNC_FAILURE_RETRY=PASS");
    assert(pthread_barrier_init(&staged, NULL, 2) == 0);
    pause_sync = 1;
    assert(pthread_create(&worker, NULL, old_writer, &first) == 0);
    sync_barrier();
    gps_client_stopping(&client);
    gps_client_end(&client);
    assert(gps_client_begin(&client));
    sync_barrier();
    assert(pthread_join(worker, NULL) == 0);
    pause_sync = 0;
    assert(pthread_barrier_destroy(&staged) == 0);
    check_file(base+120000); no_temps();
    puts("STALE_EPOCH_PUBLICATION=PASS");
    gps_client_epoch second = gps_client_ticket(&client, 0);
    assert(save(second, 1, base+180000) == 1);
    assert(pthread_create(&worker, NULL, reader, NULL) == 0);
    for (int i = 4; i < 36; ++i)
        assert(save(second, 1, base+60000LL*i) == 1);
    atomic_store(&reader_done, 1);
    assert(pthread_join(worker, NULL) == 0);
    check_file(base+60000LL*35); no_temps(); puts("ATOMIC_CONCURRENT_READS=PASS");
    gps_client_detach(&client, f[0]);
    assert(save(second, 1, base+60000LL*36) == 0);
    check_file(base+60000LL*35); no_temps();
    assert(save(0, 0, base+60000LL*36) == 1);
    check_file(base+60000LL*36); puts("DETACH_AND_STANDALONE=PASS");
    /* Rename failure must not change the watermark or leak a temporary file. */
    assert(unlink(path) == 0 && mkdir(path, 0700) == 0);
    assert(save(0, 0, base+60000LL*37) == -1); no_temps();
    assert(rmdir(path) == 0);
    assert(save(0, 0, base+60000LL*37) == 1);
    check_file(base+60000LL*37); puts("RENAME_FAILURE_RETRY=PASS");
    gps_client_send(&client, second, "OLD\n", 4);
    close(f[0]); close(f[1]);
    assert(unlink(path) == 0 && rmdir(dir) == 0);
    return 0;
}
