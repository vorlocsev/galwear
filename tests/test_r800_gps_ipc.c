#define _GNU_SOURCE
#define R800_GPS_BRIDGE_HOST_TEST 1
#include <assert.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/tools/gps/gps_ipc.h"
static int listener(void) {
    struct sockaddr_un a={.sun_family=AF_UNIX,.sun_path="./gps.sock"};
    int s=socket(AF_UNIX,SOCK_STREAM,0);
    assert(s>=0 && !bind(s,(struct sockaddr*)&a,sizeof(a)));
    assert(!chmod("gps.sock",0660));
    assert(!listen(s,2));
    return s;
}
int main(void) {
    char dir[]="/tmp/gps-ipc.XXXXXX";
    assert(mkdtemp(dir) && !chdir(dir));
    int lock=gps_ipc_lock(".");
    assert(lock>=0 && gps_ipc_lock(".")<0);
    assert(!gps_ipc_recover(lock,"./gps.sock"));
    int s=listener();
    assert(gps_ipc_recover(lock,"./gps.sock")<0);
    assert(!gps_ipc_record(lock));
    assert(gps_ipc_recover(lock,"./gps.sock")<0);
    close(s);
    assert(!gps_ipc_recover(lock,"./gps.sock"));
    assert(access("gps.sock",F_OK)<0 && access("gps.sock.owner",F_OK)<0);
    s=listener(); assert(!gps_ipc_record(lock)); close(s);
    assert(!unlink("gps.sock")); s=listener();
    assert(gps_ipc_recover(lock,"./gps.sock")<0);
    close(s); assert(!unlink("gps.sock") && !unlink("gps.sock.owner"));
    int f=open("gps.sock",O_CREAT|O_WRONLY,0600); assert(f>=0); close(f);
    assert(gps_ipc_recover(lock,"./gps.sock")<0 && !access("gps.sock",F_OK));
    assert(!unlink("gps.sock"));
    assert(!symlink("missing","gps.sock"));
    assert(gps_ipc_recover(lock,"./gps.sock")<0 && !unlink("gps.sock"));
    close(lock); assert(!chdir("/") && !rmdir(dir));
    puts("GPS_IPC_OWNERSHIP=PASS");
}
