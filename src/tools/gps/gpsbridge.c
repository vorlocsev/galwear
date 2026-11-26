/*
 * gpsbridge: runs inside the Tizen chroot and drives the BCM47758 GNSS through
 * Broadcom's client library (libbrcm.so, the same one Tizen's lbs plugin uses).
 * libbrcm exports gps_get_hardware_interface(), i.e. the classic Android GPS HAL
 * interface (hardware/gps.h), talking to Broadcom's gpsd, which talks to lhd.
 *
 *   gpsbridge [seconds]    start a standalone 1 Hz session, print NMEA and fixes
 *   gpsbridge daemon       serve /opt/usr/r800dev/gps.sock for gps.r800.so:
 *                          commands START / STOP / TIME <utc_ms> [<elapsed_ms> <unc_ms>]
 *                          / LOC <lat> <lon> <acc_m>; sends
 *                          FIX <flags> <lat> <lon> <alt> <spd> <brg> <acc> <utc_ms>,
 *                          NMEA <utc_ms> <sentence>, STATUS <n>
 *
 * Before each session the engine gets what Tizen's lbs plugin gives it: the
 * (network-synced) time, the LTO orbit file and the last fix as a position seed.
 * Without them every start was a full cold start (~3 min outdoors).
 *
 * Built against the Tizen rootfs glibc (armv7 soft-float) with no Tizen headers
 * or C runtime: the few libc calls are declared here and _start is our own.
 */
#include "gps_frame.h"
#include "gps_command.h"
#include "gps_lto.h"
#include "gps_output.h"

typedef unsigned int size_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long pthread_t;

/* ---- libc / libdl / libpthread (Tizen glibc 2.24) ---- */
int printf(const char *, ...);
int fflush(void *);
void *dlopen(const char *, int);
void *dlsym(void *, const char *);
char *dlerror(void);
int pthread_create(pthread_t *, const void *, void *(*)(void *), void *);
void *malloc(size_t);
void free(void *);
unsigned int sleep(unsigned int);
int atoi(const char *);
void exit(int);
int clock_gettime(int, void *);
int __libc_start_main(int (*main)(int, char **, char **), int, char **, void (*)(void),
		      void (*)(void), void (*)(void), void *);
#define RTLD_NOW 2
int snprintf(char *, size_t, const char *, ...);
int socket(int, int, int);
int bind(int, const void *, unsigned int);
int listen(int, int);
int accept(int, void *, unsigned int *);
long send(int, const void *, size_t, int);
int shutdown(int, int);
int close(int);
long read(int, void *, size_t);
long write(int, const void *, size_t);
int unlink(const char *);
int chmod(const char *, unsigned int);
long long strtoll(const char *, char **, int);
double strtod(const char *, char **);
int open(const char *, int, ...);
int rename(const char *, const char *);
int mkstemp(char *);
int fsync(int);
long syscall(long, ...);
#define O_RDONLY 0
#define O_NONBLOCK 04000
#define O_NOFOLLOW 0100000 /* Linux ARM UAPI, not asm-generic */
#define O_CLOEXEC 02000000
#define O_WRONLY_CREAT_TRUNC 01101
int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);
char *strchr(const char *, int);
void *memmove(void *, const void *, size_t);
int pthread_mutex_lock(void *);
int pthread_mutex_unlock(void *);
#define AF_UNIX 1
#define SOCK_STREAM 1
#define MSG_DONTWAIT 0x40
#define MSG_NOSIGNAL 0x4000
#define SHUT_RDWR 2
#define SOCK_PATH "/opt/usr/r800dev/gps.sock"

/* glibc ARM32 pthread_mutex_t (24 bytes), zero = default mutex. */
typedef int gps_client_mutex_t[8];
#define GPS_CLIENT_MUTEX_INIT {0}
#include "gps_client.h"
static struct gps_client connection = GPS_CLIENT_INIT;
static void out(gps_client_epoch epoch, const char *line, int len)
{
	gps_client_send(&connection, epoch, line, len);
}
static int daemon_mode;

#include "gps_abi.h"

#define GPS_POSITION_MODE_STANDALONE 0
#define GPS_POSITION_RECURRENCE_PERIODIC 0

#define LTO_PATH "/opt/gnss/data/lto2.dat"
/* last fix "<lat> <lon> <utc_ms>", handed back to the engine as a position seed */
#define LAST_PATH "/opt/usr/r800dev/gps.last"
#define LAST_TMP LAST_PATH ".XXXXXX"

#include "gps_cache.h"
#include "gps_cache_read.h"
#include "gps_cache_arm_stat.h"
#include "gps_lto_file.h"
static struct gps_cache position_cache = GPS_CACHE_INIT;

static void save_fix(const GpsLocation *l, gps_client_epoch epoch)
{
	char tmp[] = LAST_TMP;
	if (!(l->flags & 1))
		return;
	gps_cache_save(&position_cache, &connection, epoch, daemon_mode,
	               LAST_PATH, tmp, l->latitude, l->longitude, l->timestamp);
}

static void location_cb(GpsLocation *l)
{
	gps_client_epoch epoch = gps_client_ticket(&connection, 0);
	char b[200];
	int n;
	if (daemon_mode && !epoch)
		return;
	if (!l || l->size < sizeof(*l) || !gps_valid_seed(l->latitude, l->longitude, l->timestamp))
		return;
	n = snprintf(b, sizeof(b), "FIX %u %.8f %.8f %.2f %.3f %.2f %.2f %lld\n",
			 l->flags, l->latitude, l->longitude, l->altitude, (double)l->speed,
			 (double)l->bearing, (double)l->accuracy, l->timestamp);
	if (n > 0 && n < (int)sizeof(b))
		out(epoch, b, n);
	save_fix(l, epoch);
	if (daemon_mode)
		return;
	printf("FIX flags=%x lat=%.7f lon=%.7f alt=%.1f spd=%.2f brg=%.1f acc=%.1f t=%lld\n",
	       l->flags, l->latitude, l->longitude, l->altitude, (double)l->speed,
	       (double)l->bearing, (double)l->accuracy, l->timestamp);
	fflush(0);
}
static void status_cb(GpsStatus *s)
{
	gps_client_epoch epoch = gps_client_ticket(&connection, 1);
	char b[32];
	if ((daemon_mode && !epoch) || !s || s->size < sizeof(*s))
		return;
	out(epoch, b, snprintf(b, sizeof(b), "STATUS %u\n", s->status));
	if (daemon_mode)
		return;
	printf("STATUS %u\n", s->status);
	fflush(0);
}
static void sv_status_cb(void *sv)
{
	(void)sv;
}
static void nmea_cb(GpsUtcTime t, const char *nmea, int len)
{
	gps_client_epoch epoch = gps_client_ticket(&connection, 0);
	char b[300];
	int n;
	if (daemon_mode && !epoch)
		return;
	len = gps_nmea_length(nmea, len);
	if (len <= 0 || t < 0 || t > GPS_UTC_MAX)
		return;
	n = snprintf(b, sizeof(b), "NMEA %lld %.*s\n", t, len, nmea);
	if (n > 0 && n < (int)sizeof(b))
		out(epoch, b, n);
	if (!daemon_mode) {
		printf("NMEA %.*s\n", len, nmea);
		fflush(0);
	}
}

static void caps_cb(uint32_t c)
{
	printf("CAPS %x\n", c);
	fflush(0);
}
static void wl_acquire(void) {}
static void wl_release(void) {}
static void utc_cb(void) {}

struct thr { void (*fn)(void *); void *arg; };
static void *thr_tramp(void *p)
{
	struct thr *t = p;
	void (*fn)(void *) = t->fn;
	void *arg = t->arg;
	free(t);
	fn(arg);
	return 0;
}
static pthread_t create_thread_cb(const char *name, void (*fn)(void *), void *arg)
{
	pthread_t th = 0;
	struct thr *t;
	if (!fn)
		return 0;
	t = malloc(sizeof(*t));
	if (!t)
		return 0;
	t->fn = fn;
	t->arg = arg;
	if (pthread_create(&th, 0, thr_tramp, t) != 0) {
		free(t);
		return 0;
	}
	printf("THREAD %s\n", name ? name : "?");
	fflush(0);
	return th;
}

static GpsCallbacks cbs = {
	sizeof(GpsCallbacks), location_cb, status_cb, sv_status_cb, nmea_cb, caps_cb,
	wl_acquire, wl_release, create_thread_cb, utc_cb,
};

static const GpsInterface *gps;
static int gps_initialized;

/* clock in ms: 0 = REALTIME, 1 = MONOTONIC (libbrcm's elapsed clock), 7 = BOOTTIME
 * (Android's elapsedRealtime) */
static int64_t clk_ms(int id)
{
	struct { long sec, nsec; } ts = { 0, 0 };
	if (clock_gettime(id, &ts) != 0)
		return -1;
	return (int64_t)ts.sec * 1000 + ts.nsec / 1000000;
}

/*
 * inject_time(utc, ref, unc): ref is the engine's elapsed clock (libbrcm's
 * GpsHalGetTimer64 = CLOCK_MONOTONIC in ms) at the moment utc was valid. With ref 0
 * the time looks hours stale and the engine kept its own clock (running from
 * 00:00, learning the time only from the satellites).
 * boot_ref: Android's elapsedRealtime (CLOCK_BOOTTIME) for utc, or 0 for "now".
 */
static int inject_utc(int64_t utc, int64_t boot_ref, int unc)
{
	int64_t mono = clk_ms(1);
	int r;
	if (utc <= 0 || utc > GPS_UTC_MAX || unc < 0 || mono < 0)
		return -1;
	if (boot_ref > 0) {
		int64_t boot = clk_ms(7);
		if (boot < boot_ref || boot - boot_ref > GPS_UTC_MAX - utc)
			return -1;
		utc += boot - boot_ref;
	}
	r = gps->inject_time(utc, mono, unc);
	printf("inject_time %lld ref %lld unc %d -> %d\n", utc, mono, unc, r);
	fflush(0);
	return r;
}
/* the system clock is network-synced (Android NTP / the phone) */
#define inject_now() inject_utc(clk_ms(0), 0, 500)

#include "gps_xtra.h"
static void xtra_download_cb(void) {}
static GpsXtraCallbacks xcbs = {
#if R800_XTRA_ABI == 2
	sizeof(GpsXtraCallbacks),
#endif
	.download_request_cb = xtra_download_cb,
	.create_thread_cb = 0,
};
static char lto_buf[GPS_LTO_LIMIT];
static const GpsXtraInterface *xtra;

/* load lto2.dat into the engine (what Tizen's plugin does after downloading it) */
static void inject_lto(void)
{
	int n, r;
	enum gps_xtra_result result;
	/* Never infer the proprietary callback layout from the extension size. */
	if (R800_XTRA_ABI == 0)
		return;
	n = gps_lto_file(LTO_PATH, lto_buf, sizeof(lto_buf));
	if (n <= 0) {
		printf("lto: missing, unsafe, oversized or changed file\n");
		fflush(0);
		return;
	}
	xcbs.create_thread_cb = cbs.create_thread_cb;
	result = gps_xtra_submit(gps, &xtra, &xcbs, lto_buf, n, &r);
	if (result != XTRA_OK && result != XTRA_INJECT_FAILED) {
		printf("lto: XTRA unavailable or init failed (%d, %d)\n", result, r);
		fflush(0);
		return;
	}
	printf("lto: injected %d bytes -> %d\n", n, r);
	fflush(0);
}

/* seed the engine with the last fix: accuracy grows with its age */
static void inject_last(void)
{
	double lat, lon;
	int64_t t, age, now = clk_ms(0);
	float acc;
	int r;
	if (!gps_cache_load(&position_cache, LAST_PATH, now, &lat, &lon, &t, &acc))
		return;
	age = now - t;
	r = gps->inject_location(lat, lon, acc);
	printf("inject_location (last fix, %lld min old) acc %.0f -> %d\n", age / 60000,
	       (double)acc, r);
	fflush(0);
}

/* everything Tizen gives the engine before a session: time, orbits, position */
static void aid(void)
{
	inject_now();
	inject_lto();
	inject_last();
}

/* Enable wire callbacks immediately before start: HAL may call back
 * synchronously. End the epoch before retrying or cleaning up. */
static int daemon_start(void)
{
	int r;
	if (!gps_client_begin(&connection))
		return -1;
	r = gps->start();
	if (r != 0)
		gps_client_end(&connection);
	return r;
}

static int session(int on)
{
	int r;
	if (!on) {
		gps_client_stopping(&connection);
		r = gps->stop();
		gps_client_end(&connection);
		printf("session stop -> %d\n", r);
		fflush(0);
		return r;
	}
	aid();
	r = gps->set_position_mode(GPS_POSITION_MODE_STANDALONE,
				   GPS_POSITION_RECURRENCE_PERIODIC, 1000, 0, 0);
	if (r == 0)
		r = daemon_start();
	if (r != 0) {
		/* gpsd restarted under us: reconnect the client library and retry */
		printf("start failed, re-init\n");
		fflush(0);
		xtra = 0;
		gps_initialized = 0;
		gps->cleanup();
		r = gps->init(&cbs);
		printf("re-init %d\n", r);
		fflush(0);
		if (r != 0)
			return r;
		gps_initialized = 1;
		aid();
		r = gps->set_position_mode(GPS_POSITION_MODE_STANDALONE,
				       GPS_POSITION_RECURRENCE_PERIODIC, 1000, 0, 0);
		if (r == 0)
			r = daemon_start();
	}
	printf("session %s -> %d\n", on ? "start" : "stop", r);
	fflush(0);
	return r;
}

static int serve(void)
{
	struct { unsigned short fam; char path[108]; } a;
	int ls = socket(AF_UNIX, SOCK_STREAM, 0), i;
	const char *p = SOCK_PATH;

	a.fam = AF_UNIX;
	for (i = 0; p[i] && i < 107; i++)
		a.path[i] = p[i];
	a.path[i] = 0;
	unlink(SOCK_PATH);
	if (ls < 0 || bind(ls, &a, sizeof(a)) < 0 || listen(ls, 2) < 0) {
		printf("cannot listen on %s\n", SOCK_PATH);
		return 1;
	}
	chmod(SOCK_PATH, 0666);
	printf("listening on %s\n", SOCK_PATH);
	fflush(0);
	for (;;) {
		char buf[256];
		struct gps_frame frame = {{0}, 0};
		int on = 0, fatal = 0;
		int c = accept(ls, 0, 0);
		if (c < 0)
			continue;
		if (!gps_client_attach(&connection, c)) {
			close(c);
			close(ls);
			unlink(SOCK_PATH);
			return 1;
		}
		printf("client connected\n");
		fflush(0);
		for (;;) {
			long n = read(c, buf, sizeof(buf));
			if (n <= 0)
				break;
			for (long j = 0; j < n; j++) {
				int state = gps_frame_byte(&frame, (unsigned char)buf[j]);
				char *s = frame.line;
				if (state < 0)
					goto disconnected;
				if (state == 0)
					continue;
				/* Do not dispatch another buffered command after output shutdown. */
				if (!gps_client_matches(&connection, c))
					goto disconnected;
				if (!strcmp(s, "START") && !on) {
					if (session(1) != 0) {
						fatal = 1;
						goto disconnected;
					}
					on = 1;
				} else if (!strcmp(s, "STOP") && on) {
					if (session(0) != 0) {
						fatal = 1;
						goto disconnected;
					}
					on = 0;
				} else if (!strncmp(s, "TIME ", 5)) {
					/* TIME <utc_ms> [<elapsedRealtime_ms> <unc_ms>] */
					struct gps_time_command t;
					if (!gps_parse_time(s + 5, &t))
						goto disconnected;
					inject_utc(t.utc, t.elapsed, t.uncertainty);
				} else if (!strncmp(s, "LOC ", 4)) {
					/* LOC <lat> <lon> <acc_m>: Android's network location */
					struct gps_loc_command loc;
					if (!gps_parse_loc(s + 4, &loc))
						goto disconnected;
					float acc = (float)loc.accuracy;
					int r = gps->inject_location(loc.lat, loc.lon, acc);
					printf("inject_location (android) acc %.0f -> %d\n",
					       (double)acc, r);
					fflush(0);
				}
				frame.used = 0;
			}
		}
disconnected:
		gps_client_detach(&connection, c);
		close(c);
		if (fatal || (on && session(0) != 0)) {
			/* Unknown engine state: fail closed rather than accept a new client. */
			close(ls);
			unlink(SOCK_PATH);
			return 1;
		}
		printf("client gone\n");
		fflush(0);
	}
}

int main(int argc, char **argv, char **envp)
{
	int secs;
	void *lib = dlopen("/usr/lib/libbrcm.so", RTLD_NOW);
	const GpsInterface *(*get)(void);
	int r;

	daemon_mode = argc > 1 && !strcmp(argv[1], "daemon");
	secs = argc > 1 && !daemon_mode ? atoi(argv[1]) : 90;

	(void)envp;
	if (!lib) {
		printf("dlopen: %s\n", dlerror());
		return 1;
	}
	get = (const GpsInterface *(*)(void))dlsym(lib, "gps_get_hardware_interface");
	if (!get) {
		printf("dlsym: %s\n", dlerror());
		return 1;
	}
	gps = get();
	printf("GpsInterface %p size %u\n", (void *)gps, gps ? gps->size : 0);
	fflush(0);
	if (!gps || gps->size < sizeof(GpsInterface) || !gps->init ||
	    !gps->start || !gps->stop || !gps->cleanup || !gps->inject_time ||
	    !gps->inject_location || !gps->set_position_mode)
		return 1;
	/* Restore the persisted watermark before init can invoke callbacks. */
	{
		double lat, lon;
		int64_t utc;
		float acc;
		gps_cache_load(&position_cache, LAST_PATH, clk_ms(0), &lat, &lon, &utc, &acc);
	}
	r = gps->init(&cbs);
	printf("init %d\n", r);
	if (r != 0)
		return 1;
	gps_initialized = 1;
	if (daemon_mode) {
		inject_now();
		r = serve();
		if (gps_initialized) {
			gps_initialized = 0;
			gps->cleanup();
		}
		return r;
	}
	aid();
	r = gps->set_position_mode(GPS_POSITION_MODE_STANDALONE, GPS_POSITION_RECURRENCE_PERIODIC,
				   1000, 0, 0);
	printf("set_position_mode %d\n", r);
	if (r != 0) {
		gps->cleanup();
		return 1;
	}
	r = gps->start();
	printf("start %d (running %d s)\n", r, secs);
	fflush(0);
	if (r != 0) {
		gps->cleanup();
		return 1;
	}
	sleep(secs);
	r = gps->stop();
	printf("stop %d\n", r);
	fflush(0);
	if (r == 0)
		sleep(2);
	gps->cleanup();
	return r == 0 ? 0 : 1;
}

/* glibc ARM _start: argc/argv from the stack, rtld_fini in r0 */
__attribute__((naked, noreturn)) void _start(void)
{
	__asm__ volatile(
		"mov fp, #0\n"
		"mov lr, #0\n"
		"pop {r1}\n"		/* argc */
		"mov r2, sp\n"		/* argv */
		"push {r2}\n"		/* stack_end */
		"push {r0}\n"		/* rtld_fini */
		"mov ip, #0\n"
		"push {ip}\n"		/* fini */
		"mov r3, #0\n"		/* init */
		"ldr r0, =main\n"
		"bl __libc_start_main\n"
		"udf #0\n");
}
