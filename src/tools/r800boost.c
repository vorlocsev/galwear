/*
 * r800boost: touch boost for the SM-R800 (2x Cortex-A53, one cpufreq policy).
 *
 * The stock power HAL here is the do-nothing default, so nothing raises the CPU
 * when a finger lands: schedutil only ramps after it has seen the load, and the
 * first frames of every swipe miss their deadline. This daemon watches the
 * touchscreen and buttons, pins scaling_min_freq to the top frequency on the
 * first event, and drops it back BOOST_MS after the last one.
 *
 * GPU: when the Mali governor owns the clock (GPU_SCALE: dvfs_min_lock reads
 * -1 at start), the GPU is locked to GPU_BOOST MHz for the same window. From
 * its 100 MHz idle the Interactive governor needs several frames to ramp, and
 * those are the dropped frames at the start of every swipe. If the helper pins
 * the GPU instead, the lock is left alone.
 *
 * BOOST_MS covers the fling animation that keeps running after the finger
 * lifts (the last input event), not just the touch itself.
 *
 *   r800boost [-t ms] <eventN> [eventN ...]   (run as root from android-helper.sh)
 */
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/input.h>

#define POLICY   "/sys/devices/system/cpu/cpufreq/policy0/"
#define GPU      "/sys/class/misc/mali0/device/"
#define BOOST_MS 1000
#define GPU_BOOST "667"
#define MAX_DEV  8
#define MAX_BOOST_MS 5000
static volatile sig_atomic_t stopping;

static void stop(int sig) { (void)sig; stopping = 1; }

static int write_str(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	int ok;
	if (fd < 0)
		return -1;
	ok = write(fd, s, strlen(s)) == (ssize_t)strlen(s);
	close(fd);
	return ok ? 0 : -1;
}

static int read_str(const char *path, char *buf, size_t len)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;
	if (fd < 0)
		return -1;
	n = read(fd, buf, len - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	if ((size_t)n == len - 1 || memchr(buf, '\0', n))
		return -1;
	buf[strcspn(buf, "\n")] = 0;
	return 0;
}

/* Kernel readback is either "-1" or "effective / requested".
 * Restore only our own request, not a newer setting from another owner. */
static int gpu_requested(const char *s)
{
	int effective, requested;
	char extra;
	if (!strcmp(s, "-1"))
		return 0;
	if (sscanf(s, "%d / %d %c", &effective, &requested, &extra) != 2 ||
	    effective <= 0 || requested < 0)
		return -1;
	return requested;
}

static int restore_if_owned(const char *path, const char *expected, const char *previous)
{
	char current[32];
	if (read_str(path, current, sizeof(current)))
		return -1;
	if (strcmp(current, expected))
		return 0;
	return write_str(path, previous);
}

static int restore_gpu(void)
{
	char state[32];
	if (read_str(GPU "dvfs_min_lock", state, sizeof(state)))
		return -1;
	if (gpu_requested(state) != 667)
		return 0;
	return write_str(GPU "dvfs_min_lock", "0");
}

static long long now_ms(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000LL + t.tv_nsec / 1000000;
}

int main(int argc, char **argv)
{
	struct pollfd pfd[MAX_DEV];
	char max_f[32], min_f[32];
	char gpu_lock[32] = "";
	int n = 0, boosted = 0, i, gpu = 0, boost_ms = BOOST_MS;
	int cpu_owned = 0, gpu_owned = 0, failed = 0;
	struct sigaction sa = { .sa_handler = stop };
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGTERM, &sa, NULL) || sigaction(SIGINT, &sa, NULL) || sigaction(SIGHUP, &sa, NULL))
		return 1;
	long long until = 0;

	if (read_str(POLICY "cpuinfo_max_freq", max_f, sizeof(max_f)) ||
	    read_str(POLICY "scaling_min_freq", min_f, sizeof(min_f))) {
		fprintf(stderr, "r800boost: cannot read %s\n", POLICY);
		return 1;
	}
	if (read_str(GPU "dvfs_min_lock", gpu_lock, sizeof(gpu_lock)) == 0 &&
	    strcmp(gpu_lock, "-1") == 0)
		gpu = 1;
	for (i = 1; i < argc && n < MAX_DEV; i++) {
		int fd;
		if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
			boost_ms = atoi(argv[++i]);
			if (boost_ms < 50 || boost_ms > MAX_BOOST_MS) {
				fprintf(stderr, "invalid boost duration (50..5000 ms)\n");
				return 1;
			}
			continue;
		}
		fd = open(argv[i], O_RDONLY | O_CLOEXEC | O_NONBLOCK);
		if (fd < 0) {
			perror(argv[i]);
			continue;
		}
		pfd[n].fd = fd;
		pfd[n].events = POLLIN;
		n++;
	}
	if (!n)
		return 1;
	fprintf(stderr, "r800boost: %d devices, boost %s kHz, rest %s kHz, %d ms, gpu %s\n",
		n, max_f, min_f, boost_ms, gpu ? GPU_BOOST " MHz" : "left alone");

	while (!stopping) {
		int timeout = -1, r, activity = 0;
		if (boosted) {
			long long left = until - now_ms();
			timeout = left > 0 ? (int)left : 0;
		}
		r = poll(pfd, n, timeout);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			failed = 1;
			break;
		}
		if (r > 0) {
			struct input_event ev[16];
			for (i = 0; i < n; i++) {
				if (pfd[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
					failed = 1;
					break;
				}
				if (pfd[i].revents & POLLIN) {
					for (int budget = 16; budget > 0; budget--) {
						ssize_t bytes = read(pfd[i].fd, ev, sizeof(ev));
						if (bytes < 0 && (errno == EAGAIN || errno == EINTR))
							break;
						if (bytes <= 0 || bytes % sizeof(ev)) {
							failed = 1;
							break;
						}
						for (size_t j = 0; j < (size_t)bytes / sizeof(ev[0]); j++)
							if (ev[j].type == EV_KEY || ev[j].type == EV_ABS)
								activity = 1;
					}
				}
			}
			if (failed || stopping)
				break;
		}
		if (activity) {
			if (!boosted) {
				char state[32];
				if (!read_str(POLICY "scaling_min_freq", state, sizeof(state)) &&
				    !strcmp(state, min_f) && strcmp(min_f, max_f))
					cpu_owned = !write_str(POLICY "scaling_min_freq", max_f);
				if (gpu && !read_str(GPU "dvfs_min_lock", state, sizeof(state)) &&
				    gpu_requested(state) == 0 && !strcmp(state, "-1"))
					gpu_owned = !write_str(GPU "dvfs_min_lock", GPU_BOOST);
				boosted = 1;
			}
			until = now_ms() + boost_ms;
		}
		if (boosted && now_ms() >= until) {
			if (cpu_owned && restore_if_owned(POLICY "scaling_min_freq", max_f, min_f)) {
				failed = 1;
				break;
			}
			cpu_owned = 0;
			if (gpu_owned && restore_gpu()) {
				failed = 1;
				break;
			}
			gpu_owned = 0;
			boosted = 0;
		}
	}
	if (cpu_owned && restore_if_owned(POLICY "scaling_min_freq", max_f, min_f))
		failed = 1;
	if (gpu_owned && restore_gpu())
		failed = 1;
	for (i = 0; i < n; i++)
		close(pfd[i].fd);
	return failed ? 1 : 0;
}
