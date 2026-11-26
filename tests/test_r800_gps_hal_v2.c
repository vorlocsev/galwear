/* Real HAL, synthetic v2 peer. Native fixture, not Android ABI evidence. */
#define R800_GPS_IPC_V2 1
#define main basic_lifecycle_main
#include "test_r800_gps_hal_lifecycle.c"
#undef main

static atomic_int v2_fixes, v2_begins, v2_ends;
static void v2_fix(GpsLocation *loc)
{
    assert(loc->latitude==52 && loc->longitude==5);
    atomic_fetch_add(&v2_fixes,1);
}
static void v2_status(GpsStatus *s)
{
    if (s->status==GPS_STATUS_SESSION_BEGIN) atomic_fetch_add(&v2_begins,1);
    if (s->status==GPS_STATUS_SESSION_END) atomic_fetch_add(&v2_ends,1);
}
static void count(atomic_int *p,int n)
{
    for (int i=0;i<500 && atomic_load(p)<n;++i) usleep(10000);
    assert(atomic_load(p)==n);
}
static void put(int fd,const char *s)
{
    while (*s) {
        ssize_t n=send(fd,s,strlen(s),MSG_NOSIGNAL);
        if (n<0 && errno==EINTR) continue;
        assert(n>0); s+=n;
    }
}
static void expect(int fd,const char *s)
{
    while (*s) {
        char b;
        await_readable(fd);
        assert(recv(fd,&b,1,0)==1 && b==*s++);
    }
}
static int peer(int ls)
{
    await_readable(ls);
    int fd=accept(ls,NULL,NULL);
    assert(fd>=0);
    expect(fd,"HELLO 2\n");
    return fd;
}

int main(void)
{
    char dir[]="/tmp/r800-gps-v2.XXXXXX";
    struct sockaddr_un a={0};
    assert(mkdtemp(dir));
    assert(snprintf(test_path,sizeof(test_path),"%s/sock",dir)>0);
    int ls=socket(AF_UNIX,SOCK_STREAM,0);
    assert(ls>=0);
    a.sun_family=AF_UNIX;
    strcpy(a.sun_path,test_path);
    assert(!bind(ls,(struct sockaddr *)&a,sizeof(a)));
    assert(!listen(ls,2));
    GpsCallbacks c={.size=sizeof(c),.create_thread_cb=spawn,
                    .location_cb=v2_fix,.status_cb=v2_status};
    assert(!iface.init(&c));
    assert(!iface.start());
    int fd=peer(ls);
    assert(iface.inject_time(123,1,50)==-ENOTCONN);
    put(fd,"READY 2\n");
    expect(fd,"START 1\n");
    put(fd,"DATA 1 FIX 1 53 6 0 0 0 0 123\nACK START 1\nDATA 1 FIX 1 52 5 0 0 0 0 123\n");
    count(&v2_begins,1); count(&v2_fixes,1);
    assert(!iface.stop());
    expect(fd,"STOP 1\n");
    put(fd,"DATA 1 FIX 1 53 6 0 0 0 0 123\nACK STOP 1\n");
    count(&v2_ends,1);
    assert(!iface.start());
    expect(fd,"START 2\n");
    put(fd,"ACK START 2\nDATA 1 FIX 1 53 6 0 0 0 0 123\nDATA 2 FIX 1 52 5 0 0 0 0 123\n");
    count(&v2_begins,2); count(&v2_fixes,2);
    close(fd);
    fd=peer(ls);
    count(&v2_ends,2);
    /* Missing READY must expire, not send a legacy START. */
    struct pollfd p={fd,POLLIN,0};
    assert(poll(&p,1,7000)>0);
    char b;
    assert(recv(fd,&b,1,0)==0);
    close(fd);
    fd=peer(ls);
    put(fd,"READY 2\n");
    expect(fd,"START 1\n");
    put(fd,"ACK START 1\nDATA 1 FIX 1 52 5 0 0 0 0 123\n");
    count(&v2_begins,3); count(&v2_fixes,3);
    iface.cleanup();
    await_readable(fd);
    assert(recv(fd,&b,1,0)==0);
    close(fd); close(ls); unlink(test_path); rmdir(dir);
    puts("GPS_HAL_V2_PEER=PASS");
    return 0;
}
