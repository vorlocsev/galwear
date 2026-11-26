#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#define R800_GPS_BRIDGE_HOST_TEST 1
#include "../src/tools/gps/gps_shutdown.h"

static void *signal_thread(void *arg)
{
    (void)arg;
    usleep(50000);
    assert(raise(SIGTERM)==0);
    return NULL;
}

int main(void)
{
    int fds[2];
    char byte;
    pthread_t thread;
    assert(gps_shutdown_install()==0);
    assert(pipe(fds)==0);
    assert(write(fds[1],"x",1)==1);
    assert(gps_wait_readable(fds[0])==1);
    assert(read(fds[0],&byte,1)==1 && byte=='x');
    assert(pthread_create(&thread,NULL,signal_thread,NULL)==0);
    assert(gps_wait_readable(fds[0])==0);
    assert(pthread_join(thread,NULL)==0);
    assert(gps_shutdown_pending());
    assert(gps_wait_readable(fds[0])==0);
    close(fds[0]); close(fds[1]);
    puts("GPS_SHUTDOWN_GATE=PASS");
    return 0;
}
