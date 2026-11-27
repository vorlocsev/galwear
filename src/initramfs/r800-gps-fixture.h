/* Test-only legacy GPS HAL ABI and synthetic socket server. */
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
typedef struct {
    size_t size; uint16_t flags;
    double latitude, longitude, altitude;
    float speed, bearing, accuracy; int64_t timestamp;
} test_location;
typedef struct { size_t size; uint16_t status; } test_status;
typedef struct {
    size_t size; int16_t svid; uint8_t constellation;
    float cn0, elevation, azimuth; uint8_t flags;
} test_sv;
typedef struct { size_t size; int count; test_sv sv[64]; } test_sv_status;
typedef struct {
    size_t size;
    void (*location)(test_location *);
    void (*status)(test_status *);
    void (*legacy_sv)(void *);
    void (*nmea)(int64_t,const char *,int);
    void (*capabilities)(uint32_t);
    void (*acquire)(void);
    void (*release)(void);
    pthread_t (*create_thread)(const char *,void (*)(void *),void *);
    void (*request_time)(void);
    void (*system_info)(const void *);
    void (*gnss_sv)(void *);
} test_callbacks;
typedef struct {
    size_t size;
    int (*init)(test_callbacks *);
    int (*start)(void);
    int (*stop)(void);
    void (*cleanup)(void);
    int (*inject_time)(int64_t,int64_t,int);
    int (*inject_location)(double,double,float);
    void (*delete_aiding)(uint16_t);
    int (*set_mode)(uint32_t,uint32_t,uint32_t,uint32_t,uint32_t);
    const void *(*extension)(const char *);
} test_gps_interface;
struct test_gps_device {
    hw_device_t common;
    const test_gps_interface *(*get_interface)(struct test_gps_device *);
};
static atomic_int gps_bad,gps_fixes,gps_nmea,gps_sv,gps_caps,gps_begin,gps_end,gps_barrier;
static void (*gps_reader)(void *);
static void *gps_reader_arg;
static void gps_location_cb(test_location *l)
{
    if (!l || l->size != sizeof(*l) || l->flags != 31 ||
        l->latitude != 12.5 || l->longitude != -34.5 || l->altitude != 10 ||
        l->speed != 2 || l->bearing != 90 || l->accuracy != 3 ||
        l->timestamp != INT64_C(1700000000123)) atomic_store(&gps_bad,1);
    atomic_fetch_add(&gps_fixes,1);
}
static void gps_status_cb(test_status *s)
{
    if (!s || s->size != sizeof(*s)) { atomic_store(&gps_bad,1); return; }
    if (s->status == 1) atomic_fetch_add(&gps_begin,1);
    else if (s->status == 2) atomic_fetch_add(&gps_end,1);
    else if (s->status == 3) atomic_fetch_add(&gps_barrier,1);
    else atomic_store(&gps_bad,1);
}
static void gps_caps_cb(uint32_t v)
{
    if (v != 1) atomic_store(&gps_bad,1);
    atomic_fetch_add(&gps_caps,1);
}
static void gps_nmea_cb(int64_t t,const char *s,int n)
{
    if (t != INT64_C(1700000000123) || !s || n <= 0 ||
        n != (int)strlen(s) || *s != '$') atomic_store(&gps_bad,1);
    atomic_fetch_add(&gps_nmea,1);
}
static void gps_sv_cb(void *p)
{
    test_sv_status *s = p;
    if (!s || s->size != sizeof(*s) || s->count != 1 ||
        s->sv[0].size != sizeof(test_sv) || s->sv[0].svid != 3 ||
        s->sv[0].constellation != 1 || s->sv[0].cn0 != 35 ||
        s->sv[0].elevation != 45 || s->sv[0].azimuth != 120 ||
        s->sv[0].flags != 4) atomic_store(&gps_bad,1);
    atomic_fetch_add(&gps_sv,1);
}
static void *gps_thread_main(void *unused)
{
    (void)unused;
    gps_reader(gps_reader_arg);
    return NULL;
}
static pthread_t gps_create_thread(const char *name,void (*entry)(void *),void *arg)
{
    (void)name;
    pthread_t thread = 0;
    gps_reader = entry; gps_reader_arg = arg;
    if (pthread_create(&thread,NULL,gps_thread_main,NULL)) {
        atomic_store(&gps_bad,1); return 0;
    }
    pthread_detach(thread);
    return thread;
}
static test_callbacks gps_callbacks = {
    .size=sizeof(test_callbacks),.location=gps_location_cb,.status=gps_status_cb,
    .nmea=gps_nmea_cb,.capabilities=gps_caps_cb,.create_thread=gps_create_thread,.gnss_sv=gps_sv_cb
};
#define GPS_FIXTURE "/oem/r800dev"
#define GPS_SOCKET GPS_FIXTURE "/gps.sock"
static int gps_send_bytes(int fd,const void *data,size_t len)
{
    const char *p=data;
    while (len) {
        ssize_t n=send(fd,p,len,MSG_NOSIGNAL);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return 0;
        p+=n; len-=(size_t)n;
    }
    return 1;
}
static int gps_line(int fd,const char *s) { return gps_send_bytes(fd,s,strlen(s)); }
static int gps_expect(int fd,const char *s)
{
    for (;*s;++s) {
        struct pollfd p={.fd=fd,.events=POLLIN};
        char ch;
        if (poll(&p,1,4000)!=1 || read(fd,&ch,1)!=1 || ch!=*s) return 0;
    }
    return 1;
}
static int gps_accept(int fd)
{
    struct pollfd p={.fd=fd,.events=POLLIN};
    return poll(&p,1,5000)==1 ? accept(fd,NULL,NULL) : -1;
}
static int gps_wait(int expected)
{
    for (int i=0;i<400;++i) {
        if (atomic_load(&gps_bad)) return 0;
        if (atomic_load(&gps_barrier)==expected) return 1;
        usleep(10000);
    }
    return 0;
}
static int gps_sentence(int fd,const char *body)
{
    unsigned sum=0;
    for (const char *p=body;*p;++p) sum^=(unsigned char)*p;
    char s[256];
    int n=snprintf(s,sizeof(s),"NMEA 1700000000123 $%s*%02X\n",body,sum);
    return n>0 && n<(int)sizeof(s) && gps_send_bytes(fd,s,(size_t)n);
}
static int gps_fixture(const hw_module_t *module)
{
    if (!fixture_read(GPS_FIXTURE "/.galwear-fixture","GALWEAR_GPS_FIXTURE_V1\n") ||
        !missing(GPS_SOCKET)) return 90;
    int server=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);
    struct sockaddr_un a={.sun_family=AF_UNIX};
    memcpy(a.sun_path,GPS_SOCKET,sizeof(GPS_SOCKET));
    if (server<0 || bind(server,(struct sockaddr *)&a,sizeof(a)) || listen(server,2)) return 91;
    hw_device_t *base=NULL;
    if (module->methods->open(module,"gps",&base) || !base ||
        base->tag!=HARDWARE_DEVICE_TAG || base->module!=module || !base->close) return 92;
    struct test_gps_device *dev=(struct test_gps_device *)base;
    if (!dev->get_interface) return 93;
    const test_gps_interface *api=dev->get_interface(dev);
    if (!api || api->size!=sizeof(*api) || !api->init || !api->start || !api->stop ||
        !api->inject_time || !api->inject_location) return 94;
    if (api->init(&gps_callbacks) || api->start() || atomic_load(&gps_caps)!=1 ||
        atomic_load(&gps_begin)!=1) return 95;
    int peer=gps_accept(server);
    if (peer<0 || !gps_expect(peer,"START\n")) return 96;
    if (api->inject_time(1700000000123LL,1000,10) ||
        !gps_expect(peer,"TIME 1700000000123 1000 10\n") ||
        api->inject_location(12.5,-34.5,3) || !gps_expect(peer,"LOC 12.500000 -34.500000 3\n") ||
        api->inject_time(-1,0,0)!=-EINVAL || api->inject_location(91,0,1)!=-EINVAL) return 97;
    static const char invalid[]="FIX 31 91 -34.5 10 2 90 3 1700000000123\n"
        "NMEA 1700000000123 $GPRMC,1*00\nFIX 31 12.5\0 -34.5 10 2 90 3 1700000000123\n";
    char longline[4200];
    memset(longline,'x',sizeof(longline)); longline[sizeof(longline)-1]='\n';
    if (!gps_send_bytes(peer,invalid,sizeof(invalid)-1) ||
        !gps_send_bytes(peer,longline,sizeof(longline)) ||
        !gps_line(peer,"FIX 31 12.5 -34.5 10 ") || !gps_line(peer,"2 90 3 1700000000123\n") ||
        !gps_sentence(peer,"GPGSV,1,1,1,03,45,120,35") ||
        !gps_sentence(peer,"GPGSA,A,3,03,,,,,,,,,,,,1.0,1.0,1.0") ||
        !gps_sentence(peer,"GPRMC,1") || !gps_line(peer,"STATUS 3\n") || !gps_wait(1) ||
        atomic_load(&gps_fixes)!=1 || atomic_load(&gps_nmea)!=3 || atomic_load(&gps_sv)!=1) return 98;
    if (close(peer)) return 99;
    peer=gps_accept(server);
    if (peer<0 || !gps_expect(peer,"START\n") ||
        !gps_line(peer,"FIX 31 12.5 -34.5 10 2 90 3 1700000000123\nSTATUS 3\n") ||
        !gps_wait(2) || atomic_load(&gps_fixes)!=2 || atomic_load(&gps_nmea)!=3 ||
        atomic_load(&gps_sv)!=1) return 100;
    if (api->stop() || !gps_expect(peer,"STOP\n") ||
        atomic_load(&gps_end)!=1 || atomic_load(&gps_bad)) return 101;
    if (base->close(base) || close(peer) || close(server) || unlink(GPS_SOCKET)) return 102;
    puts("HAL_GPS_FIXTURE_PASS fixes=2 nmea=3 sv=1 reconnect=1 commands=5");
    return 0;
}
