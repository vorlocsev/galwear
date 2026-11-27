/* Native snapshot tests, no proprietary LTO data or HAL execution. */
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
#include "gps_lto.h"
#include "gps_lto_file.h"

static char dir[] = "/tmp/r800-lto-XXXXXX", path[128], other[128];
static char payload[GPS_LTO_LIMIT+1], buffer[GPS_LTO_LIMIT];
static int mutate, calls;
static int gps_cache_stat(int fd, struct gps_cache_meta *out)
{
    struct stat s;
    if (fstat(fd, &s)) return -1;
    *out = (struct gps_cache_meta){s.st_mode, s.st_nlink, s.st_size,
        s.st_mtim.tv_sec, s.st_mtim.tv_nsec, s.st_ctim.tv_sec, s.st_ctim.tv_nsec};
    if (mutate && ++calls == 1) {
        int w = open(path, O_WRONLY | O_APPEND);
        assert(w >= 0 && write(w, "x", 1) == 1 && close(w) == 0);
    }
    return 0;
}
static void replace(size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    assert(fd >= 0 && write(fd, payload, len) == (ssize_t)len && close(fd) == 0);
}
static int load(void) { return gps_lto_file(path, buffer, sizeof(buffer)); }
int main(void)
{
    assert(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/lto2.dat", dir);
    snprintf(other, sizeof(other), "%s/other", dir);
    memset(payload, 0x5a, sizeof(payload));
    assert(load() == -1);
    replace(0); assert(load() == -1);
    replace(1); assert(load() == 1 && buffer[0] == 0x5a);
    replace(sizeof(buffer)); assert(load() == (int)sizeof(buffer));
    assert(memcmp(payload, buffer, sizeof(buffer)) == 0);
    replace(sizeof(payload)); assert(load() == -1);
    puts("LTO_SIZE_BOUNDS=PASS");
    replace(32);
    assert(gps_lto_file(path, buffer, 0) == -1);
    assert(gps_lto_file(path, buffer, GPS_LTO_LIMIT+1) == -1);
    assert(gps_lto_file(path, buffer, 31) == -1);
    assert(gps_lto_file(path, buffer, 32) == 32);
    puts("LTO_CAPACITY=PASS");
    assert(chmod(path,0644)==0 && load()==32);
    assert(chmod(path,0664)==0 && load()==-1);
    assert(chmod(path,0666)==0 && load()==-1);
    assert(chmod(path,0600)==0 && link(path,other)==0 && load()==-1);
    assert(unlink(other)==0 && rename(path,other)==0);
    assert(symlink(other,path)==0 && load()==-1);
    assert(unlink(path)==0 && mkfifo(path,0600)==0 && load()==-1);
    assert(unlink(path)==0 && mkdir(path,0700)==0 && load()==-1);
    assert(rmdir(path)==0 && rename(other,path)==0);
    puts("LTO_TYPE_LINK_MODE=PASS");
    mutate=1; calls=0;
    assert(load()==-1);
    mutate=0;
    assert(load()==33 && buffer[32]=='x');
    puts("LTO_CHANGED_DURING_READ=PASS");
    assert(unlink(path)==0 && rmdir(dir)==0);
    return 0;
}
