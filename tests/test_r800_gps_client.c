/* Host test of the actual shared GPS Bridge socket transport, no ARM HAL. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef pthread_mutex_t gps_client_mutex_t;
#define GPS_CLIENT_MUTEX_INIT PTHREAD_MUTEX_INITIALIZER
#include "gps_client.h"

static struct gps_client c = GPS_CLIENT_INIT;

struct producer { const char *kind; };
static void *produce(void *arg)
{
    const struct producer *p = arg;
    for (int i = 0; i < 32; ++i) {
        char line[32];
        int n = snprintf(line, sizeof(line), "%s %02d\n", p->kind, i);
        assert(n > 0 && n < (int)sizeof(line));
        gps_client_send(&c, line, n);
    }
    return NULL;
}

static void concurrent_frames(void)
{
    int f[2], next[2] = {0, 0};
    pthread_t workers[2];
    struct producer producers[2] = {{"FIX"}, {"NMEA"}};
    char line[32], byte;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0);
    assert(gps_client_attach(&c, f[0]));
    assert(!gps_client_attach(&c, f[1]));
    for (int i = 0; i < 2; ++i)
        assert(pthread_create(&workers[i], NULL, produce, &producers[i]) == 0);
    for (int i = 0; i < 2; ++i)
        assert(pthread_join(workers[i], NULL) == 0);
    assert(gps_client_matches(&c, f[0]));
    gps_client_detach(&c, f[0]);
    close(f[0]);
    int used = 0;
    while (read(f[1], &byte, 1) == 1) {
        assert(used < (int)sizeof(line)-1);
        line[used++] = byte;
        if (byte == '\n') {
            char expected[32];
            int k = line[0] == 'F' ? 0 : 1;
            line[used] = 0;
            snprintf(expected, sizeof(expected), "%s %02d\n", producers[k].kind, next[k]++);
            assert(strcmp(line, expected) == 0);
            used = 0;
        }
    }
    assert(used == 0 && next[0] == 32 && next[1] == 32);
    close(f[1]);
}

static void disconnected_peer(void)
{
    int f[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0);
    assert(gps_client_attach(&c, f[0]));
    close(f[1]);
    gps_client_send(&c, "FIX\n", 4);
    assert(!gps_client_matches(&c, f[0]));
    /* The callback must not close the serve loop's descriptor. */
    assert(close(f[0]) == 0);
    gps_client_detach(&c, f[0]);
}

static pthread_barrier_t disconnected;

static void *send_after_disconnect(void *arg)
{
    const char *line = arg;
    int r = pthread_barrier_wait(&disconnected);
    assert(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
    gps_client_send(&c, line, (int)strlen(line));
    return NULL;
}

static void concurrent_disconnect(void)
{
    for (int i = 0; i < 32; ++i) {
        int f[2], r;
        pthread_t a, b;
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0);
        assert(gps_client_attach(&c, f[0]));
        assert(pthread_barrier_init(&disconnected, NULL, 3) == 0);
        assert(pthread_create(&a, NULL, send_after_disconnect, "FIX\n") == 0);
        assert(pthread_create(&b, NULL, send_after_disconnect, "NMEA\n") == 0);
        close(f[1]);
        r = pthread_barrier_wait(&disconnected);
        assert(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
        assert(pthread_join(a, NULL) == 0);
        assert(pthread_join(b, NULL) == 0);
        assert(pthread_barrier_destroy(&disconnected) == 0);
        assert(!gps_client_matches(&c, f[0]));
        assert(close(f[0]) == 0);
    }
}

static void saturated_peer(void)
{
    int f[2], small = 4096;
    char buf[128];
    memset(buf, 'x', sizeof(buf));
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0);
    assert(setsockopt(f[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small)) == 0);
    assert(gps_client_attach(&c, f[0]));
    for (int i = 0; i < 2048 && gps_client_matches(&c, f[0]); ++i)
        gps_client_send(&c, buf, sizeof(buf));
    assert(!gps_client_matches(&c, f[0]));
    assert(close(f[0]) == 0);
    close(f[1]);
}

static void detach_and_reconnect(void)
{
    int f[2];
    char buf[4];
    for (int i = 0; i < 64; ++i) {
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, f) == 0);
        assert(gps_client_attach(&c, f[0]));
        gps_client_detach(&c, f[1]);
        assert(gps_client_matches(&c, f[0]));
        gps_client_send(&c, "FIX\n", 4);
        assert(recv(f[1], buf, sizeof(buf), MSG_WAITALL) == 4);
        assert(memcmp(buf, "FIX\n", 4) == 0);
        gps_client_detach(&c, f[0]);
        gps_client_send(&c, "BAD\n", 4);
        assert(recv(f[1], buf, sizeof(buf), MSG_DONTWAIT) == -1);
        assert(errno == EAGAIN || errno == EWOULDBLOCK);
        close(f[0]);
        close(f[1]);
    }
}

int main(void)
{
    concurrent_frames(); puts("CONCURRENT_FRAMES=PASS");
    disconnected_peer(); puts("DISCONNECTED_PEER=PASS");
    concurrent_disconnect(); puts("CONCURRENT_DISCONNECT_32=PASS");
    saturated_peer(); puts("SATURATED_PEER=PASS");
    detach_and_reconnect(); puts("RECONNECT_64=PASS");
    return 0;
}
