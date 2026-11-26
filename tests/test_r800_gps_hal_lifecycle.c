/* Actual reader lifecycle with a synthetic local Unix socket; no Android ABI claim. */
#define _GNU_SOURCE
#include <assert.h>
#include <poll.h>
#include <stdatomic.h>
static char test_path[108];
#define SOCK_PATH test_path
#define R800_GPS_HOST_TEST 1
/* Legacy fixture explicitly exercises v1 unless another mode is requested. */
#if !defined(R800_GPS_IPC_V2) && !defined(R800_GPS_TEST_SOURCE_DEFAULT)
#define R800_GPS_IPC_V2 0
#endif
#include "../src/hal/gps_r800.c"
struct launch { void (*fn)(void *); void *arg; };
static void *run_thread(void *arg)
{
    struct launch *p=arg;
    void (*fn)(void *)=p->fn;
    void *data=p->arg;
    free(p);
    fn(data);
    return NULL;
}
static pthread_t spawn(const char *name,void (*fn)(void *),void *arg)
{
    pthread_t th;
    pthread_attr_t attr;
    struct launch *p=malloc(sizeof(*p));
    (void)name;
    assert(p);
    p->fn=fn; p->arg=arg;
    assert(!pthread_attr_init(&attr));
    assert(!pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED));
    assert(!pthread_create(&th,&attr,run_thread,p));
    assert(!pthread_attr_destroy(&attr));
    return th;
}
static pthread_t fail_spawn(const char *name,void (*fn)(void *),void *arg)
{
    (void)name; (void)fn; (void)arg;
    return 0;
}
static atomic_int fixes;
static void fix(GpsLocation *loc)
{
    assert(loc->flags==1 && loc->latitude==52 && loc->longitude==5);
    atomic_fetch_add(&fixes,1);
}
static void self_cleanup(uint32_t flags)
{
    (void)flags;
    gps_cleanup();
}
static void await_readable(int fd)
{
    struct pollfd p={fd,POLLIN,0};
    assert(poll(&p,1,5000)>0);
}
int main(void)
{
    char dir[]="/tmp/r800-gps-test.XXXXXX";
    struct sockaddr_un a={0};
    GpsCallbacks c={0};
    int ls,fd;
    char line[6];
    assert(mkdtemp(dir));
    assert(snprintf(test_path,sizeof(test_path),"%s/sock",dir)>0);
    assert(gps_init(NULL)==-EINVAL);
    assert(gps_start()==-ENODEV);
    c.size=offsetof(GpsCallbacks,set_system_info_cb);
    c.create_thread_cb=fail_spawn;
    assert(gps_init(&c)==-EAGAIN);
    c.create_thread_cb=spawn;
    assert(!gps_init(&c));
    assert(gps_init(&c)==-EBUSY);
    gps_cleanup();
    assert(!gps_init(&c));
    gps_cleanup();
    c.set_capabilities_cb=self_cleanup;
    assert(!gps_init(&c));
    gps_cleanup();
    c.set_capabilities_cb=NULL;
    ls=socket(AF_UNIX,SOCK_STREAM,0);
    assert(ls>=0);
    a.sun_family=AF_UNIX;
    strcpy(a.sun_path,test_path);
    assert(!bind(ls,(struct sockaddr *)&a,sizeof(a)));
    assert(!listen(ls,1));
    c.location_cb=fix;
    assert(!gps_init(&c));
    c.location_cb=NULL; /* HAL must have copied the table */
    assert(!gps_start());
    await_readable(ls);
    fd=accept(ls,NULL,NULL);
    assert(fd>=0);
    await_readable(fd);
    assert(recv(fd,line,sizeof(line),MSG_WAITALL)==sizeof(line));
    assert(!memcmp(line,"START\n",sizeof(line)));
    const char msg[]="FIX 1 52 5 0 0 0 0 123\n";
    assert(send(fd,msg,sizeof(msg)-1,MSG_NOSIGNAL)==sizeof(msg)-1);
    for (int i=0;i<500 && !atomic_load(&fixes);i++) usleep(10000);
    assert(atomic_load(&fixes)==1);
    gps_cleanup();
    await_readable(fd);
    assert(recv(fd,line,sizeof(line),0)==0);
    assert(!gps_init(&c));
    gps_cleanup();
    close(fd); close(ls); unlink(test_path); rmdir(dir);
    puts("GPS_HAL_LIFECYCLE=PASS");
    return 0;
}
