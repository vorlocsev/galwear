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

#ifdef R800_GPS_BRIDGE_HOST_TEST
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#define GPS_MUTEX(name) static pthread_mutex_t name = PTHREAD_MUTEX_INITIALIZER
#define GPS_PEER_UID ((unsigned int)getuid())
#define GPS_PEER_GID ((unsigned int)getgid())
#define SOCK_PATH "./gps.sock"
#define GPS_IPC_DIR "."
#define GPS_BRIDGE_LIB "./libbrcm-test.so"
#else
typedef unsigned int size_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
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
long recv(int, void *, size_t, int);
int shutdown(int, int);
int close(int);
long read(int, void *, size_t);
long write(int, const void *, size_t);
int unlink(const char *);
int chmod(const char *, unsigned int);
int chown(const char *, unsigned int, unsigned int);
unsigned int umask(unsigned int);
unsigned int getuid(void);
int getsockopt(int, int, int, void *, unsigned int *);
#define SOL_SOCKET 1
#define SO_PEERCRED 17
long long strtoll(const char *, char **, int);
double strtod(const char *, char **);
int open(const char *, int, ...);
int rename(const char *, const char *);
int mkstemp(char *);
int fsync(int);
#define O_RDONLY 0
#define O_NONBLOCK 04000
#define O_NOFOLLOW 0100000 /* Linux ARM UAPI, not asm-generic */
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
/* Freestanding QEMU fixture changes only paths, never the ABI/CRT.
 * Do not use this configuration for deployment. */
#ifdef R800_GPS_FREESTANDING_FIXTURE
#define SOCK_PATH "./gps.sock"
#define GPS_IPC_DIR "."
#define GPS_BRIDGE_LIB "./libbrcm-test.so"
#else
#define SOCK_PATH "/opt/usr/r800dev/gps.sock"
#define GPS_IPC_DIR "/opt/usr/r800dev"
#define GPS_BRIDGE_LIB "/usr/lib/libbrcm.so"
#endif
#define GPS_MUTEX(name) static int name[8]
#ifndef R800_GPS_PEER_UID
#define R800_GPS_PEER_UID -1
#endif
#ifndef R800_GPS_PEER_GID
#define R800_GPS_PEER_GID -1
#endif
#define GPS_PEER_UID ((unsigned int)R800_GPS_PEER_UID)
#define GPS_PEER_GID ((unsigned int)R800_GPS_PEER_GID)
#endif

#include "gps_ipc.h"
#include "gps_server_v2.h"

/* daemon: the connected gps.r800.so, or -1 */
static int client = -1;
static enum gps_server_mode client_mode;
static unsigned int client_data_id;
GPS_MUTEX(mtx);   /* target glibc default mutex; native pthread in fixture */

/* Caller holds mtx. Only the serve loop closes the descriptor. */
static int send_locked(const char *line, int len)
{
	if (client < 0) return -1;
	if (len <= 0 || send(client, line, (size_t)len, MSG_DONTWAIT | MSG_NOSIGNAL) != len) {
		shutdown(client, SHUT_RDWR);
		client = -1;
		client_data_id = 0;
		return -1;
	}
	return 0;
}

static void out(const char *line, int len)
{
	pthread_mutex_lock(&mtx);
	if (client >= 0 && len > 0) {
		if (client_mode == GPS_SERVER_V1) {
			send_locked(line, len);
		} else if (client_mode == GPS_SERVER_V2 && client_data_id) {
			char framed[GPS_FRAME_CAPACITY];
			int n = snprintf(framed, sizeof(framed), "DATA %u %.*s",
					 client_data_id, len, line);
			if (n <= 0 || n >= (int)sizeof(framed) || n > GPS_FRAME_CAPACITY-1)
				send_locked("", 0);
			else
				send_locked(framed, n);
		}
	}
	pthread_mutex_unlock(&mtx);
}

/* Publish v2 data ID only after successful ACK START, in the same lock
 * as callback writes. STOP closes the channel before the vendor call. */
static int protocol_publish(enum gps_server_mode mode, unsigned int id,
                            const char *reply, int len)
{
	int r = 0;
	pthread_mutex_lock(&mtx);
	client_mode = mode;
	client_data_id = 0;
	if (client < 0 || (reply && send_locked(reply, len) != 0))
		r = -1;
	else
		client_data_id = id;
	pthread_mutex_unlock(&mtx);
	return r;
}

static int daemon_mode;

#include "gps_abi.h"
#include "gps_interface_gate.h"
#include "gps_standalone.h"
#include "gps_daemon.h"
#include "gps_shutdown.h"
#include "gps_callback_gate.h"

GPS_MUTEX(callback_mtx);
static enum gps_callback_phase callback_phase = GPS_CALLBACK_CLOSED;

static void set_callback_phase(enum gps_callback_phase phase)
{
	pthread_mutex_lock(&callback_mtx);
	callback_phase = phase;
	pthread_mutex_unlock(&callback_mtx);
}

#define GPS_POSITION_MODE_STANDALONE 0
#define GPS_POSITION_RECURRENCE_PERIODIC 0

#if defined(R800_GPS_BRIDGE_HOST_TEST) || defined(R800_GPS_FREESTANDING_FIXTURE)
#define LTO_PATH "./lto2.dat"
#define LAST_PATH "./gps.last"
#else
#define LTO_PATH "/opt/gnss/data/lto2.dat"
#define LAST_PATH "/opt/usr/r800dev/gps.last"
#endif
#define LAST_TMP LAST_PATH ".XXXXXX"

static GpsUtcTime last_saved;   /* utc ms of the last fix written to LAST_PATH */
GPS_MUTEX(save_mtx);

static void save_fix(const GpsLocation *l)
{
	char b[80], tmp[] = LAST_TMP;
	int fd, n, ok;
	if (!(l->flags & 1) || !gps_valid_seed(l->latitude, l->longitude, l->timestamp))
		return;
	pthread_mutex_lock(&save_mtx);
	if (l->timestamp <= last_saved || l->timestamp - last_saved < 60000)
		goto done;
	n = snprintf(b, sizeof(b), "%.6f %.6f %lld\n", l->latitude, l->longitude, l->timestamp);
	if (n <= 0 || n >= (int)sizeof(b))
		goto done;
	fd = mkstemp(tmp); /* unique regular file, mode 0600 */
	if (fd < 0)
		goto done;
	ok = write(fd, b, n) == n && fsync(fd) == 0;
	if (close(fd) != 0)
		ok = 0;
	if (ok && rename(tmp, LAST_PATH) == 0)
		last_saved = l->timestamp;
	else
		unlink(tmp);
done:
	pthread_mutex_unlock(&save_mtx);
}

static void emit_location(GpsLocation *l)
{
	char b[200];
	int n;
	if (!l || l->size < sizeof(*l) || !gps_valid_seed(l->latitude, l->longitude, l->timestamp))
		return;
	n = snprintf(b, sizeof(b), "FIX %u %.8f %.8f %.2f %.3f %.2f %.2f %lld\n",
			 l->flags, l->latitude, l->longitude, l->altitude, (double)l->speed,
			 (double)l->bearing, (double)l->accuracy, l->timestamp);
	if (n > 0 && n < (int)sizeof(b))
		out(b, n);
	save_fix(l);
	if (daemon_mode)
		return;
	printf("FIX flags=%x lat=%.7f lon=%.7f alt=%.1f spd=%.2f brg=%.1f acc=%.1f t=%lld\n",
	       l->flags, l->latitude, l->longitude, l->altitude, (double)l->speed,
	       (double)l->bearing, (double)l->accuracy, l->timestamp);
	fflush(0);
}
static void emit_status(GpsStatus *s)
{
	char b[32];
	if (!s || s->size < sizeof(*s))
		return;
	out(b, snprintf(b, sizeof(b), "STATUS %u\n", s->status));
	if (daemon_mode)
		return;
	printf("STATUS %u\n", s->status);
	fflush(0);
}
static void sv_status_cb(void *sv)
{
	(void)sv;
}
static void emit_nmea(GpsUtcTime t, const char *nmea, int len)
{
	char b[300];
	int n;
	len = gps_nmea_length(nmea, len);
	if (len <= 0 || t < 0 || t > GPS_UTC_MAX)
		return;
	n = snprintf(b, sizeof(b), "NMEA %lld %.*s\n", t, len, nmea);
	if (n > 0 && n < (int)sizeof(b))
		out(b, n);
	if (!daemon_mode) {
		printf("NMEA %.*s\n", len, nmea);
		fflush(0);
	}
}

/* Drain in-flight output before a phase transition. These functions never
 * invoke vendor slots while holding callback_mtx. Lock order: callback,
 * then output/save mutex; the session owner never takes the reverse order. */
static void location_cb(GpsLocation *l)
{
	pthread_mutex_lock(&callback_mtx);
	if (gps_callback_allowed(callback_phase, 0))
		emit_location(l);
	pthread_mutex_unlock(&callback_mtx);
}

static void status_cb(GpsStatus *s)
{
	pthread_mutex_lock(&callback_mtx);
	if (gps_callback_allowed(callback_phase, 1))
		emit_status(s);
	pthread_mutex_unlock(&callback_mtx);
}

static void nmea_cb(GpsUtcTime t, const char *nmea, int len)
{
	pthread_mutex_lock(&callback_mtx);
	if (gps_callback_allowed(callback_phase, 0))
		emit_nmea(t, nmea, len);
	pthread_mutex_unlock(&callback_mtx);
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

static int guarded_start(void)
{
	/* Vendor may deliver callbacks synchronously from START. */
	set_callback_phase(GPS_CALLBACK_ACTIVE);
	int rc = gps->start();
	if (rc != 0)
		set_callback_phase(GPS_CALLBACK_CLOSED);
	return rc;
}

static int guarded_stop(void)
{
	set_callback_phase(GPS_CALLBACK_STOPPING);
	int rc = gps->stop();
	set_callback_phase(GPS_CALLBACK_CLOSED);
	return rc;
}

/* clock in ms: 0 = REALTIME, 1 = MONOTONIC (libbrcm's elapsed clock), 7 = BOOTTIME
 * (Android's elapsedRealtime) */
static GpsUtcTime clk_ms(int id)
{
	#ifdef R800_GPS_BRIDGE_HOST_TEST
	struct timespec ts = { 0, 0 };
#else
	struct { long tv_sec, tv_nsec; } ts = { 0, 0 };
#endif
	if (clock_gettime(id, &ts) != 0)
		return -1;
	return (GpsUtcTime)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/*
 * inject_time(utc, ref, unc): ref is the engine's elapsed clock (libbrcm's
 * GpsHalGetTimer64 = CLOCK_MONOTONIC in ms) at the moment utc was valid. With ref 0
 * the time looks hours stale and the engine kept its own clock (running from
 * 00:00, learning the time only from the satellites).
 * boot_ref: Android's elapsedRealtime (CLOCK_BOOTTIME) for utc, or 0 for "now".
 */
static int inject_utc(GpsUtcTime utc, GpsUtcTime boot_ref, int unc)
{
	GpsUtcTime mono = clk_ms(1);
	int r;
	if (utc <= 0 || utc > GPS_UTC_MAX || unc < 0 || mono < 0)
		return -1;
	if (boot_ref > 0) {
		GpsUtcTime boot = clk_ms(7);
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

static void xtra_download_cb(void) {}
static GpsXtraCallbacks xcbs = {
#if R800_XTRA_ABI == 2
	sizeof(GpsXtraCallbacks),
#endif
	.download_request_cb = xtra_download_cb,
	.create_thread_cb = 0,
};
static char lto_buf[256 * 1024];
static long lto_read(void *ctx, char *buf, unsigned int size)
{
	return read(*(int *)ctx, buf, size);
}
static const GpsXtraInterface *xtra;

/* load lto2.dat into the engine (what Tizen's plugin does after downloading it) */
static void inject_lto(void)
{
	int fd, n = 0, r;
	/* Never infer the proprietary callback layout from the extension size. */
	if (R800_XTRA_ABI == 0)
		return;
	if (!xtra) {
		const GpsXtraInterface *candidate = gps->get_extension ? gps->get_extension("gps-xtra") : 0;
		xcbs.create_thread_cb = cbs.create_thread_cb;
		if (gps_xtra_interface_valid(candidate) && candidate->init(&xcbs) == 0)
			xtra = candidate;
	}
	if (!xtra) {
		printf("lto: no gps-xtra\n");
		fflush(0);
		return;
	}
	fd = open(LTO_PATH, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0) {
		printf("lto: no %s\n", LTO_PATH);
		fflush(0);
		return;
	}
	n = gps_read_lto(lto_read, &fd, lto_buf, sizeof(lto_buf));
	close(fd);
	if (n <= 0) {
		printf("lto: empty, oversized or unreadable\n");
		fflush(0);
		return;
	}
	r = xtra->inject_xtra_data(lto_buf, n);
	printf("lto: injected %d bytes -> %d\n", n, r);
	fflush(0);
}

/* seed the engine with the last fix: accuracy grows with its age */
static void inject_last(void)
{
	char b[96];
	double lat, lon;
	GpsUtcTime t, age, now;
	float acc;
	int fd = open(LAST_PATH, O_RDONLY | O_NONBLOCK | O_NOFOLLOW), r, n;
	if (fd < 0)
		return;
	n = gps_read_lto(lto_read, &fd, b, sizeof(b) - 1);
	close(fd);
	if (n <= 0 || !gps_parse_seed(b, n, &lat, &lon, &t))
		return;
	now = clk_ms(0);
	if (now < t)
		return;
	age = now - t;
	if (age > 30LL * 86400000 || (lat == 0 && lon == 0))
		return;
	acc = age < 86400000 ? 2000.0f : 25000.0f;
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

static enum gps_daemon_state daemon_state = GPS_DAEMON_READY;

static int standalone_configure(void);

static void daemon_cleanup(void)
{
	set_callback_phase(GPS_CALLBACK_CLOSED);
	xtra = 0;
	gps->cleanup();
}

static int daemon_reinit(void)
{
	printf("configuration failed, re-init\n");
	fflush(0);
	return gps->init(&cbs);
}

static struct gps_daemon_ops daemon_ops;

static int session(int on)
{
	int r = gps_daemon_session(&daemon_state, &daemon_ops, on);
	printf("session %s -> %d\n", on ? "start" : "stop", r);
	fflush(0);
	return r;
}

static int peer_allowed(int fd)
{
    struct { int pid; unsigned int uid, gid; } peer;
    unsigned int len = sizeof(peer);
    return getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &len) == 0 &&
           len == sizeof(peer) && peer.pid > 0 && peer.uid == GPS_PEER_UID;
}

static int serve(int dirfd)
{
	struct { unsigned short fam; char path[108]; } a;
	int ls, i;
	unsigned int previous_mask;
	if (GPS_PEER_UID == (unsigned int)-1 || GPS_PEER_GID == (unsigned int)-1)
		return 1;
	ls = socket(AF_UNIX, SOCK_STREAM | O_NONBLOCK, 0);
	const char *p = SOCK_PATH;

	for (i = 0; i < 108; ++i) a.path[i] = 0;
	a.fam = AF_UNIX;
	for (i = 0; p[i] && i < 107; i++)
		a.path[i] = p[i];
	a.path[i] = 0;
	if (ls < 0)
		return 1;
	/* Create owner-only first. Recovery has already verified any old endpoint.
	 * The parent must remain trusted throughout the daemon lifetime. */
	previous_mask = umask(0177);
	int bound = bind(ls, (const void *)&a, sizeof(a));
	umask(previous_mask);
	if (bound < 0) {
		printf("cannot bind %s (existing path or permission failure)\n", SOCK_PATH);
		close(ls);
		return 1;
	}
	if (chown(SOCK_PATH, getuid(), GPS_PEER_GID) != 0 ||
	    chmod(SOCK_PATH, 0660) != 0 || gps_ipc_record(dirfd) != 0 || listen(ls, 2) != 0) {
		printf("cannot secure/listen on %s\n", SOCK_PATH);
		close(ls);
		return 1;
	}
	printf("listening on %s\n", SOCK_PATH);
	fflush(0);
	for (;;) {
		char buf[256];
		struct gps_frame frame = {{0}, 0};
		struct gps_v2_server protocol = {0};
		int fatal = 0;
		int ready = gps_wait_readable(ls);
		if (ready <= 0) { close(ls); return ready < 0 ? 1 : 0; }
		int c = accept(ls, 0, 0);
		if (c < 0) {
			if (gps_shutdown_pending()) { close(ls); return 0; }
			if (IPC_ERRNO == EINTR || IPC_ERRNO == 11) continue;
			close(ls); return 1;
		}
		if (!peer_allowed(c)) { close(c); continue; }
		pthread_mutex_lock(&mtx);
		client = c;
		client_mode = GPS_SERVER_UNDECIDED;
		client_data_id = 0;
		pthread_mutex_unlock(&mtx);
		printf("client connected\n");
		fflush(0);
		for (;;) {
			int ready = gps_wait_readable(c);
			if (ready <= 0) { fatal = ready < 0; break; }
			long n = recv(c, buf, sizeof(buf), MSG_DONTWAIT);
			if (n < 0 && (IPC_ERRNO == EINTR || IPC_ERRNO == 11)) continue;
			if (n <= 0) break;
			for (long j = 0; j < n; j++) {
				if (gps_shutdown_pending()) goto disconnected;
				int state = gps_frame_byte(&frame, (unsigned char)buf[j]);
				char *s = frame.line;
				if (state < 0)
					goto disconnected;
				if (state == 0)
					continue;
				unsigned int id;
				enum gps_server_action action = gps_server_plan(&protocol, s, &id);
				if (action == GPS_SERVER_REJECT)
					goto disconnected;
				if (action == GPS_SERVER_READY) {
					if (protocol_publish(GPS_SERVER_V2, 0, GPS_V2_READY "\n",
							     sizeof(GPS_V2_READY "\n")-1))
						goto disconnected;
				} else if (action == GPS_SERVER_START || action == GPS_SERVER_STOP) {
					int start = action == GPS_SERVER_START;
					/* v1 permits synchronous callbacks. v2 discards
					 * callbacks until ACK START, and during STOP. */
					if (protocol_publish(protocol.mode, 0, 0, 0))
						goto disconnected;
					if (session(start) != 0) {
						fatal = 1;
						goto disconnected;
					}
					gps_server_commit(&protocol, action, id);
					if (protocol.mode == GPS_SERVER_V2) {
						char ack[40];
						int len = snprintf(ack, sizeof(ack), "ACK %s %u\n",
								   start ? "START" : "STOP", id);
						if (len <= 0 || len >= (int)sizeof(ack) ||
						    protocol_publish(GPS_SERVER_V2, start ? id : 0, ack, len))
							goto disconnected;
					}
				} else if (action == GPS_SERVER_TIME) {
					/* TIME <utc_ms> [<elapsedRealtime_ms> <unc_ms>] */
					struct gps_time_command t;
					if (!gps_parse_time(s + 5, &t))
						goto disconnected;
					inject_utc(t.utc, t.elapsed, t.uncertainty);
				} else if (action == GPS_SERVER_LOC) {
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
		pthread_mutex_lock(&mtx);
		if (client == c)
			client = -1;
		client_data_id = 0;
		client_mode = GPS_SERVER_UNDECIDED;
		pthread_mutex_unlock(&mtx);
		close(c);
		if (fatal || (protocol.active && session(0) != 0)) {
			/* Unknown engine state: fail closed rather than accept a new client. */
			close(ls);
			return 1;
		}
		if (gps_shutdown_pending()) { close(ls); return 0; }
		printf("client gone\n");
		fflush(0);
	}
}

static int standalone_configure(void)
{
	return gps->set_position_mode(GPS_POSITION_MODE_STANDALONE,
				      GPS_POSITION_RECURRENCE_PERIODIC, 1000, 0, 0);
}

int main(int argc, char **argv, char **envp)
{
	unsigned int secs = 90;
	int dirfd;
	void *lib;
	const GpsInterface *(*get)(void);
	int r;

	daemon_mode = argc > 1 && !strcmp(argv[1], "daemon");
	if (argc > 2 || (argc > 1 && !daemon_mode && !gps_standalone_duration(argv[1], &secs))) {
		printf("usage: gpsbridge [1..3600|daemon]\n");
		return 1;
	}
	if (daemon_mode && (GPS_PEER_UID == (unsigned int)-1 || GPS_PEER_GID == (unsigned int)-1)) {
		printf("GPS daemon blocked: verified Android UID/GID required\n");
		return 1;
	}
	/* Lock before vendor initialization, including standalone mode. */
	dirfd = gps_ipc_lock(GPS_IPC_DIR);
	if (dirfd < 0 || gps_ipc_recover(dirfd, SOCK_PATH) != 0) {
		printf("GPS bridge blocked: lock or socket ownership uncertain\n");
		return 1;
	}
	if (daemon_mode && gps_shutdown_install() != 0) {
		printf("GPS daemon blocked: signal handler installation failed\n");
		return 1;
	}
	lib = dlopen(GPS_BRIDGE_LIB, RTLD_NOW);

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
	if (!gps_interface_valid(gps)) {
		printf("GPS bridge blocked: incompatible interface table\n");
		fflush(0);
		return 1;
	}
	printf("GPS interface table shape accepted (ABI unverified)\n");
	fflush(0);
	r = gps->init(&cbs);
	printf("init %d\n", r);
	if (r != 0)
		return 1;
	if (daemon_mode) {
		daemon_ops = (struct gps_daemon_ops){
			aid, standalone_configure, guarded_start, guarded_stop,
			daemon_cleanup, daemon_reinit
		};
		r = 0;
		if (!gps_shutdown_pending()) {
			inject_now();
			r = serve(dirfd);
		}
		if (gps_daemon_close(&daemon_state, &daemon_ops))
			r = 1;
		if (!r && gps_ipc_recover(dirfd, SOCK_PATH) != 0)
			r = 1;
		return r;
	}
	const struct gps_standalone_ops ops = {
		aid, standalone_configure, guarded_start, sleep, guarded_stop, daemon_cleanup
	};
	r = gps_standalone_run(&ops, secs);
	printf("standalone result %d\n", r);
	fflush(0);
	return r == GPS_RUN_OK ? 0 : 1;
}

#ifndef R800_GPS_BRIDGE_HOST_TEST
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

#endif /* !R800_GPS_BRIDGE_HOST_TEST */
