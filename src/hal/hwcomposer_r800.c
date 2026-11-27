/*
 * hwcomposer.r800.so - minimal HWC 1.1 module for the Galaxy Watch SM-R800 (Exynos 9110)
 * bring-up on Wear OS 2 (Android 9).
 *
 * SurfaceFlinger composes everything on the GPU (Mali-T720) into the framebuffer
 * target. set() waits for that buffer, maps it through the gralloc module
 * (gralloc.exynos5 from the Galaxy J4), copies it into the back half of
 * /dev/graphics/fb0 and flips with FBIOPAN_DISPLAY. Vsync comes from the
 * panel's TE through DECON, with timer fill-ins on the same grid while idle.
 *
 * Loaded by android.hardware.graphics.composer@2.1-impl via hw_get_module("hwcomposer")
 * (ro.hardware = r800) and wrapped by its HWC2On1Adapter.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <math.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <time.h>
#include <unistd.h>

#include <linux/sync_file.h>
#include <arm_neon.h>
#include <android/log.h>
#include <hardware/hardware.h>
#include <hardware/gralloc.h>
#include <hardware/hwcomposer.h>

#define TAG "hwc-r800"
#include <stdarg.h>
#include <stdio.h>
/* Log to logcat AND the kernel log (bring-up: kmsg survives into Tizen's last_kmsg). */
static void hlog(int prio, const char *fmt, ...)
{
	static int kfd = -2;
	char buf[480];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	__android_log_write(prio, TAG, buf);
	if (kfd == -2)
		kfd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
	if (kfd >= 0)
		dprintf(kfd, "<3>hwc-r800: %s\n", buf);
	{
		static int ffd = -2;
		if (ffd == -2)
			ffd = open("/oem/r800dev/hwc.log",
				   O_WRONLY | O_CREAT | O_APPEND, 0644);
		if (ffd >= 0)
			dprintf(ffd, "%s\n", buf);
	}
}
#define LOGI(...) hlog(ANDROID_LOG_ERROR, __VA_ARGS__)  /* bring-up: surface in '*:W' capture */
#define LOGW(...) hlog(ANDROID_LOG_WARN, __VA_ARGS__)
#define LOGE(...) hlog(ANDROID_LOG_ERROR, __VA_ARGS__)

#define VSYNC_PERIOD_NS 16666667LL

/*
 * Zero-copy present: hand the client-target dma-buf straight to the Exynos
 * DECON with S3CFB_WIN_CONFIG (what Samsung's own HWC does). Mirrors
 * drivers/video/fbdev/exynos/dpu30/decon.h of our kernel; the ioctl number
 * encodes sizeof(struct r800_win_config_data), so a layout mismatch fails
 * with ENOTTY and we fall back to the CPU copy.
 */
#include "r800_decon_abi.h"

struct r800_hwc {
	hwc_composer_device_1_t base;      /* must be first */
	const hwc_procs_t *procs;
	const gralloc_module_t *gralloc;
	void *hardware_lib;

	int fb_fd;
	struct fb_var_screeninfo var;
	struct fb_fix_screeninfo fix;
	uint8_t *fb_mem;
	unsigned int front;                /* 0 or 1: which half is on screen */

	pthread_t vsync_thread;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	int vsync_enabled;
	unsigned long vsync_epoch;
	int vsync_stop, vsync_started;
	unsigned int callback_active, callback_waiters;
	int blanked;
	int power_unknown;                 /* failed transition: do not present until recovered */
	int real_blanked;
	int power_mode;                    /* HWC_POWER_MODE_*: last mode set */
	int logged_handle;
	unsigned long frames;
	uint64_t no_buffer;                /* layers prepare() saw as BACKGROUND/SIDEBAND */
	size_t layer_stride;                /* selected once at open */
	int allow_unknown_size;            /* explicit experimental ION compatibility */
	int swap_rb;                       /* RGBA buffers -> BGRA panel: swap R and B */
	int zerocopy;                      /* 1: S3CFB_WIN_CONFIG, 0: CPU copy + pan */
	unsigned long wc_fail;
	int fencescan_seen;                /* debug.r800.fencescan: change it to log our open fences */
	int dump_left, dump_seen;
	/* ambient: DECON is put in DOZE_SUSPEND after doze_idle_ms without a frame */
	pthread_t idle_thread;
	pthread_mutex_t doze_lock;
	pthread_cond_t doze_cond;
	int idle_stop, idle_started;
	int doze_susp;                     /* we put DECON in DOZE_SUSPEND */
	int64_t last_present_ns;
	unsigned long doze_suspends;

	/* overlays: up to R800_MAX_DECON_WIN layers straight to DECON windows */
	int fmt_verified;                  /* 1: handle format field checked on the FB target; -1: layout unknown */
	int ovl_off;                       /* overlays disabled after repeated WIN_CONFIG failures */
	int ovl_n;                         /* this frame: layers marked HWC_OVERLAY by prepare() */
	size_t ovl_idx[R800_MAX_DECON_WIN];
	unsigned long ovl_frames, gpu_frames, ovl_fail;
};

static void fb_fill(struct r800_hwc *h, uint32_t col);
static int handle_geom(buffer_handle_t hnd, int w, int ht, int *stride, int *fmt);

/* ---- gralloc (looked up at run time: the NDK has no libhardware stub) ---- */
static const gralloc_module_t *load_gralloc(struct r800_hwc *h)
{
	typedef int (*hw_get_module_t)(const char *, const struct hw_module_t **);
	void *lib = dlopen("libhardware.so", RTLD_NOW);
	if (!lib) {
		LOGE("dlopen libhardware.so: %s", dlerror());
		return NULL;
	}
	hw_get_module_t get = (hw_get_module_t)dlsym(lib, "hw_get_module");
	const struct hw_module_t *mod = NULL;
	if (!get || get(GRALLOC_HARDWARE_MODULE_ID, &mod) || !mod) {
		LOGE("hw_get_module(gralloc) failed");
		dlclose(lib);
		return NULL;
	}
	h->hardware_lib = lib;
	LOGI("gralloc module '%s' by '%s'", mod->name, mod->author);
	return (const gralloc_module_t *)mod;
}

/*
 * Row stride (pixels) of a gralloc buffer. Exynos private handles carry
 * "... width, height, stride, vstride ..." as consecutive ints; find
 * width,height and take the next int if it looks like a stride.
 */
/* Probe mapped pages, not allocation ownership or access permissions.
 * The native HWC caller must still provide valid, live handles. */
static int mapped_span(uintptr_t p, size_t len)
{
	long page = sysconf(_SC_PAGESIZE);
	if (page <= 0 || ((unsigned long)page & ((unsigned long)page - 1)) ||
	    !len || p < (uintptr_t)page || len - 1 > UINTPTR_MAX - p)
		return 0;
	uintptr_t mask = (uintptr_t)page - 1;
	uintptr_t first = p & ~mask, last = (p + len - 1) & ~mask;
	for (uintptr_t q = first;; q += (uintptr_t)page) {
		if (msync((void *)q, (size_t)page, MS_ASYNC))
			return 0;
		if (q == last)
			return 1;
	}
}

static int handle_ok(buffer_handle_t hnd)
{
	const native_handle_t *nh = (const native_handle_t *)hnd;
	uintptr_t p = (uintptr_t)hnd;
	if ((p & (sizeof(int) - 1)) || !mapped_span(p, sizeof(*nh)))
		return 0;
	if (nh->version != (int)sizeof(*nh) || nh->numFds < 1 || nh->numFds > 8 ||
	    nh->numInts < 0 || nh->numInts > 128)
		return 0;
	size_t size = sizeof(*nh) + (size_t)(nh->numFds + nh->numInts) * sizeof(int);
	return mapped_span(p, size);
}

/* Compute the full padded 32bpp plane, without ARM32 overflow. */
static int plane_bytes(int w, int ht, int stride, uint64_t *need)
{
	if (w <= 0 || ht <= 0 || w > INT_MAX - 128 || stride < w || stride > w + 128)
		return -EINVAL;
	uint64_t row = (uint64_t)stride * 4;
	if (row > SIZE_MAX || (uint64_t)ht > SIZE_MAX / row)
		return -EOVERFLOW;
	*need = row * (uint64_t)ht;
	return 0;
}

/* A known positive size must cover the full padded plane. A zero or
 * unsupported size query is not proof of capacity; allow only by opt-in. */
static int check_plane_size(uint64_t need, int64_t have, int allow_unknown)
{
	if (!need)
		return -EINVAL;
	if (have <= 0)
		return allow_unknown ? 0 : -ENODATA;
	return (uint64_t)have < need ? -ENOSPC : 0;
}

/* Legacy Exynos handle metadata is a heuristic, not a gralloc ABI.
 * Require one unambiguous geometry tuple with a supported format. */
static int handle_geom(buffer_handle_t hnd, int w, int ht, int *stride, int *fmt)
{
	if (!handle_ok(hnd) || w <= 0 || ht <= 0 || w > INT_MAX - 128)
		return -EINVAL;
	const native_handle_t *nh = (const native_handle_t *)hnd;
	const int *ints = &nh->data[nh->numFds];
	int found = 0;
	for (int i = 1; i + 2 < nh->numInts; i++) {
		if (ints[i] != w || ints[i + 1] != ht ||
		    ints[i + 2] < w || ints[i + 2] > w + 128)
			continue;
		if (found++)
			return -EINVAL;
		*stride = ints[i + 2];
		*fmt = ints[i - 1];
	}
	if (!found || (*fmt != HAL_PIXEL_FORMAT_RGBA_8888 &&
	    *fmt != HAL_PIXEL_FORMAT_RGBX_8888 && *fmt != HAL_PIXEL_FORMAT_BGRA_8888))
		return -EINVAL;
	return 0;
}

static int checked_buffer(struct r800_hwc *h, buffer_handle_t hnd,
			  int w, int ht, int *stride, int *fmt)
{
	uint64_t need;
	int r = handle_geom(hnd, w, ht, stride, fmt);
	if (r)
		return r;
	r = plane_bytes(w, ht, *stride, &need);
	if (r)
		return r;
	const native_handle_t *nh = (const native_handle_t *)hnd;
	if (nh->data[0] < 0 || fcntl(nh->data[0], F_GETFD) < 0)
		return -EBADF;
	off64_t have = lseek64(nh->data[0], 0, SEEK_END);
	if (have < 0 && errno != EINVAL && errno != ESPIPE && errno != ENOSYS)
		return -errno;
	return check_plane_size(need, have, h->allow_unknown_size);
}

/* debug.r800.fencescan: histogram of this process's open sync_file fds by
 * timeline (the hang 3 leak hunt; one composer fd leaked per frame). */
static void fence_scan(void)
{
	struct { char key[72]; int count, lo, hi, signaled; } k[16];
	int nk = 0, fd, total = 0;
	memset(k, 0, sizeof(k));
	for (fd = 0; fd < 32768; fd++) {
		struct sync_fence_info fi[2];
		struct sync_file_info info;
		char key[72];
		int j;
		memset(&info, 0, sizeof(info));
		memset(fi, 0, sizeof(fi));
		info.num_fences = 2;
		info.sync_fence_info = (uintptr_t)fi;
		if (ioctl(fd, SYNC_IOC_FILE_INFO, &info))
			continue;
		total++;
		{
			char *dash = strrchr(info.name, '-');
			if (dash && dash != info.name)
				*dash = 0;     /* drop the seqno: group by timeline */
		}
		snprintf(key, sizeof(key), "%.40s %.10s", info.name, fi[0].driver_name);
		for (j = 0; j < nk && strcmp(k[j].key, key); j++)
			;
		if (j == nk) {
			if (nk == 16)
				continue;
			strcpy(k[nk].key, key);
			k[nk].lo = fd;
			nk++;
		}
		k[j].count++;
		k[j].hi = fd;
		k[j].signaled += info.status == 1;
	}
	LOGE("fence scan: %d sync_files", total);
	for (fd = 0; fd < nk; fd++)
		LOGE("  %5d x '%s' fds %d..%d, %d signaled", k[fd].count, k[fd].key, k[fd].lo, k[fd].hi,
		     k[fd].signaled);
}

static int wait_fence(int fd)
{
	if (fd == -1)
		return 0;
	if (fd < -1)
		return -EINVAL;
	struct pollfd p = { .fd = fd, .events = POLLIN };
	int r = poll(&p, 1, 1000);
	int saved = errno;
	close(fd);
	if (r < 0)
		return -saved;
	if (r == 0)
		return -ETIMEDOUT;
	if (!(p.revents & POLLIN) || (p.revents & (POLLERR | POLLHUP | POLLNVAL)))
		return -EIO;
	return 0;
}

/* ---- framebuffer ---- */
static int fb_open(struct r800_hwc *h)
{
	h->fb_fd = open("/dev/graphics/fb0", O_RDWR | O_CLOEXEC);
	if (h->fb_fd < 0)
		h->fb_fd = open("/dev/fb0", O_RDWR | O_CLOEXEC);
	if (h->fb_fd < 0) {
		int e = errno;
		LOGE("open fb0: %s", strerror(e));
		return -e;
	}
	if (ioctl(h->fb_fd, FBIOGET_FSCREENINFO, &h->fix) || ioctl(h->fb_fd, FBIOGET_VSCREENINFO, &h->var)) {
		int e = errno;
		LOGE("FBIOGET_*SCREENINFO: %s", strerror(e));
		return -e;
	}
	/* CPU copy supports only the existing 32bpp framebuffer geometry. */
	if (!h->var.xres || !h->var.yres || h->var.bits_per_pixel != 32 ||
	    h->var.xres > INT_MAX - 128 || h->var.yres > INT_MAX || (h->fix.line_length & 3) ||
	    h->var.xres_virtual < h->var.xres || h->var.yres_virtual < h->var.yres ||
	    (uint64_t)h->var.xres * 4 > h->fix.line_length ||
	    (uint64_t)h->var.yres * h->fix.line_length > h->fix.smem_len) {
		LOGE("unsupported framebuffer geometry");
		return -EINVAL;
	}
	h->fb_mem = mmap(NULL, h->fix.smem_len, PROT_READ | PROT_WRITE, MAP_SHARED, h->fb_fd, 0);
	if (h->fb_mem == MAP_FAILED) {
		int e = errno;
		LOGE("mmap fb0 (%u bytes): %s", h->fix.smem_len, strerror(e));
		h->fb_mem = NULL;
		return -e;
	}
	LOGI("fb0 %ux%u (virt %ux%u) %ubpp line %u smem %u, %ux%u mm",
	     h->var.xres, h->var.yres, h->var.xres_virtual, h->var.yres_virtual,
	     h->var.bits_per_pixel, h->fix.line_length, h->fix.smem_len, h->var.width, h->var.height);
	/* Run 105: blue UI showed orange, so the panel takes BGRA while gralloc
	 * buffers are RGBA. Swap in the copy (FBIOPUT_VSCREENINFO could mode-set the
	 * panel, whose re-init is broken). debug.r800.swaprb=0 turns it off. */
	{
		char v[PROP_VALUE_MAX] = "";
		__system_property_get("debug.r800.swaprb", v);
		h->swap_rb = (v[0] == '0') ? 0 : 1;
		v[0] = 0;
		__system_property_get("debug.r800.zerocopy", v);
		h->zerocopy = (v[0] == '0') ? 0 : 1;
		v[0] = 0;
		__system_property_get("debug.r800.allow_unknown_size", v);
		h->allow_unknown_size = !strcmp(v, "1");
		if (h->allow_unknown_size)
			LOGW("experimental: accepting ION buffers with unverified size");
		LOGI("fb0 rgba offsets r%u g%u b%u a%u, swap_rb=%d zerocopy=%d (win_config_data %zu bytes)",
		     h->var.red.offset, h->var.green.offset, h->var.blue.offset, h->var.transp.offset,
		     h->swap_rb, h->zerocopy, sizeof(struct r800_win_config_data));
	}
	return 0;
}

static void fb_fill(struct r800_hwc *h, uint32_t col)
{
	uint32_t *px = (uint32_t *)h->fb_mem;
	size_t n32 = h->fix.smem_len / 4, i;
	if (!h->fb_mem)
		return;
	for (i = 0; i < n32; i++)
		px[i] = col;
	h->var.yoffset = 0;
	ioctl(h->fb_fd, FBIOPAN_DISPLAY, &h->var);
}

static int fb_present(struct r800_hwc *h, buffer_handle_t buf, int is_target)
{
	const unsigned int w = h->var.xres, ht = h->var.yres, bpp = h->var.bits_per_pixel / 8;
	const unsigned int halves = ((uint64_t)h->var.yres_virtual >= 2ULL * ht &&
				     (uint64_t)h->fix.smem_len >= 2ULL * ht * h->fix.line_length) ? 2 : 1;
	const unsigned int back = halves == 2 ? !h->front : 0;
	void *src = NULL;
	unsigned int y;
	int stride, err, fmt;

	if (!h->fb_mem)
		return -EIO;
	/* On any failure keep the previous frame on screen (the old debug colour
	 * fills showed up as a white screen whenever gralloc ran out of memory). */
	if (!h->gralloc || !buf)
		return -EIO;
	if (!handle_ok(buf)) {        /* not a buffer (e.g. a color): keep the last frame */
		static unsigned long bad;
		if (bad++ < 5 || (bad % 600) == 0)
			LOGW("skip %s: bad handle %p (%lu)", is_target ? "target" : "fallback", (void *)buf, bad);
		return -EIO;
	}
	if (checked_buffer(h, buf, (int)w, (int)ht, &stride, &fmt))
		return -EINVAL;
	err = h->gralloc->lock(h->gralloc, buf, GRALLOC_USAGE_SW_READ_OFTEN, 0, 0, w, ht, &src);
	if (err || !src) {
		if (!err)
			h->gralloc->unlock(h->gralloc, buf);
		static unsigned long lockfail;
		if (lockfail++ < 5 || (lockfail % 600) == 0)
			LOGW("gralloc lock failed (%d), keeping last frame (%lu)", err, lockfail);
		return -EIO;
	}
	if ((uintptr_t)src & (sizeof(uint32_t) - 1)) {
		h->gralloc->unlock(h->gralloc, buf);
		return -EINVAL;
	}
	uint8_t *dst = h->fb_mem + (size_t)back * ht * h->fix.line_length;
	/* swap_rb describes the RGBA source; BGRA needs the opposite swap. */
	if ((h->swap_rb != (fmt == HAL_PIXEL_FORMAT_BGRA_8888)) && bpp == 4) {
		/* NEON: vld4 de-interleaves 16 pixels per load (whole-line reads, which
		 * matters on the uncached GPU buffer) and R/B swap is just a register
		 * swap before vst4. The old per-pixel loop cost ~35% CPU at 60 fps. */
		for (y = 0; y < ht; y++) {
			const uint32_t *s = (const uint32_t *)((uint8_t *)src + (size_t)y * stride * bpp);
			uint32_t *o = (uint32_t *)(dst + (size_t)y * h->fix.line_length);
			unsigned int x = 0;
			for (; x + 16 <= w; x += 16) {
				uint8x16x4_t v = vld4q_u8((const uint8_t *)(s + x));
				uint8x16_t t = v.val[0];
				v.val[0] = v.val[2];
				v.val[2] = t;
				vst4q_u8((uint8_t *)(o + x), v);
			}
			for (; x < w; x++) {
				uint32_t p = s[x];
				o[x] = (p & 0xff00ff00u) | ((p & 0xffu) << 16) | ((p >> 16) & 0xffu);
			}
		}
	} else {
		for (y = 0; y < ht; y++)
			memcpy(dst + (size_t)y * h->fix.line_length, (uint8_t *)src + (size_t)y * stride * bpp, w * bpp);
	}
	if (h->gralloc->unlock(h->gralloc, buf))
		return -EIO;

	struct fb_var_screeninfo next = h->var;
	next.yoffset = back * ht;
	if (ioctl(h->fb_fd, FBIOPAN_DISPLAY, &next)) {
		LOGW("FBIOPAN_DISPLAY: %s", strerror(errno));
		return -EIO;
	}
	h->var.yoffset = next.yoffset;
	h->front = back;
	if (h->frames++ < 3 || (h->frames % 600) == 0)
		LOGI("presented frame %lu (half %u)", h->frames, back);
	return 0;
}

/* Returns 0 when DECON took the buffer; fills the layer's release fence and
 * *retire. On failure the acquire fence is left untouched for the copy path. */
static int wc_present(struct r800_hwc *h, hwc_layer_1_t *l, int *retire)
{
	const native_handle_t *nh = (const native_handle_t *)l->handle;
	const unsigned int w = h->var.xres, ht = h->var.yres;
	struct r800_win_config_data d;
	struct r800_win_config *c = &d.config[0];
	int i, stride, fmt;
	if (!l->handle || !handle_ok(l->handle) || nh->numFds < 1 || nh->data[0] < 0) {
		static unsigned long bad;
		if (l->handle && bad++ < 5)
			LOGE("zero-copy: unusable handle %p", (void *)l->handle);
		return -1;
	}
	if (checked_buffer(h, l->handle, (int)w, (int)ht, &stride, &fmt) ||
	    fmt != HAL_PIXEL_FORMAT_RGBA_8888) {
		h->fmt_verified = -1;
		return -EINVAL;
	}
	h->fmt_verified = 1;

	memset(&d, 0, sizeof(d));
	d.retire_fence = -1;
	d.fd_odma = -1;
	for (i = 0; i <= R800_MAX_DECON_WIN; i++) {
		d.config[i].state = R800_WIN_STATE_DISABLED;
		d.config[i].fd_idma[0] = d.config[i].fd_idma[1] = d.config[i].fd_idma[2] = -1;
		d.config[i].acq_fence = d.config[i].rel_fence = -1;
	}
	c->state = R800_WIN_STATE_BUFFER;
	c->fd_idma[0] = nh->data[0];
	c->acq_fence = l->acquireFenceFd;      /* DECON waits for the GPU itself */
	c->plane_alpha = 0xff;
	c->blending = R800_BLENDING_NONE;
	c->channel = 0;                        /* DT default_ch */
	c->format = R800_FMT_RGBA_8888;        /* no R/B swap needed */
	c->src = (struct r800_frame){ 0, 0, w, ht, (uint32_t)stride, ht };
	c->dst = (struct r800_frame){ 0, 0, w, ht, w, ht };

	{
		static int first = 1;
		if (first) {
			first = 0;
			LOGE("zero-copy: first WIN_CONFIG (fd %d acq %d stride %d) ioctl 0x%x",
			     c->fd_idma[0], c->acq_fence, stride, (unsigned)R800_S3CFB_WIN_CONFIG);
		}
	}
	if (ioctl(h->fb_fd, R800_S3CFB_WIN_CONFIG, &d)) {
		int e = errno;
		if (h->wc_fail++ < 5 || (h->wc_fail % 600) == 0)
			LOGE("S3CFB_WIN_CONFIG failed: %s (%lu)", strerror(e), h->wc_fail);
		if (e == ENOTTY || e == EINVAL || h->wc_fail > 20) {
			LOGE("zero-copy disabled (%s): falling back to CPU copy", strerror(e));
			h->zerocopy = 0;
		}
		return -1;
	}
	if (l->acquireFenceFd >= 0)
		close(l->acquireFenceFd);
	l->acquireFenceFd = -1;
	/* HWC2 has no release fence for the client target (the present fence
	 * releases the previous target buffer), and the retire fence returned
	 * below signals at the same point, so drop the window's release fence. */
	if (c->rel_fence >= 0)
		close(c->rel_fence);
	l->releaseFenceFd = -1;
	*retire = d.retire_fence;
	if (h->frames++ < 3 || (h->frames % 1800) == 0)
		LOGI("zero-copy frame %lu (stride %d, rel %d, retire %d)", h->frames, stride,
		     c->rel_fence, d.retire_fence);
	return 0;
}

/*
 * Layer stride: the caller's ABI is an explicit startup contract.
 * Do not probe a second stride by reading beyond the caller array.
 */
/* Only the ARM32 prefix of the donor layer is assumed to match AOSP.
 * Do not probe an alternative stride by reading beyond the caller array. */
_Static_assert(sizeof(void *) == 4, "R800 composer requires ARM32");
_Static_assert(sizeof(hwc_layer_1_t) == 96, "AOSP layer size");
_Static_assert(offsetof(hwc_layer_1_t, handle) == 12, "handle offset");
_Static_assert(offsetof(hwc_layer_1_t, acquireFenceFd) == 64, "acquire offset");
_Static_assert(offsetof(hwc_layer_1_t, releaseFenceFd) == 68, "release offset");
_Static_assert(offsetof(hwc_display_contents_1_t, hwLayers) == 20, "layer array offset");

#define R800_MAX_LAYERS 256
#define R800_MAX_DISPLAYS 3

static size_t select_layer_stride(const char *property)
{
	/* The existing J4 donor contract is the historical default. */
	if (!property[0] || !strcmp(property, "100"))
		return 100;
	if (!strcmp(property, "96"))
		return 96;
	return 0;
}

#define LAYER(c, i) ((hwc_layer_1_t *)((char *)(c)->hwLayers + (size_t)(i) * h->layer_stride))

static int validate_display(struct r800_hwc *h, const hwc_display_contents_1_t *c, int primary)
{
	if (!c)
		return 0;
	if (c->numHwLayers > R800_MAX_LAYERS)
		return -EINVAL;
	if (primary && c->numHwLayers) {
		size_t i;
		for (i = 0; i < c->numHwLayers; i++) {
			if ((LAYER(c, i)->compositionType == HWC_FRAMEBUFFER_TARGET) !=
			    (i == c->numHwLayers - 1))
				return -EINVAL;
		}
	}
	return 0;
}

static int validate_displays(struct r800_hwc *h, size_t n, hwc_display_contents_1_t **displays)
{
	if (n > R800_MAX_DISPLAYS || (n && !displays))
		return -EINVAL;
	for (size_t i = 0; i < n; i++)
		if (validate_display(h, displays[i], i == 0))
			return -EINVAL;
	return 0;
}

/*
 * ---- Overlays (2026-11-18) ----
 * SurfaceFlinger composed every frame on the GPU (all layers CLIENT): a 37 s
 * scroll trace had it in drawLayers for 36.9 s, and the single Mali-T720
 * core it shares with the apps ran at 667 MHz whenever the screen moved.
 * DECON has 3 windows / 3 DPP channels that blend in hardware, so when every
 * layer is a plain buffer (no scaling, no transform, RGBA/RGBX/BGRA, on
 * screen) and there are at most 3 of them, prepare() marks them all
 * HWC_OVERLAY and set() hands each to its own window, bottom layer first.
 * Anything else falls back to GPU composition for the whole frame.
 * vendor.hwc.r800.overlay=1 explicitly enables this experimental path.
 *
 * Pixel format: the Exynos private handle has "... format, width, height,
 * stride ..." as consecutive ints. Geometry and padded capacity are
 * checked on every submission; this remains a donor-layout heuristic.
 */
static int ovl_enabled(struct r800_hwc *h)
{
	char v[PROP_VALUE_MAX] = "";
	if (h->ovl_off || h->fmt_verified != 1 || !h->zerocopy || h->blanked ||
	    h->power_mode != HWC_POWER_MODE_NORMAL)
		return 0;
	__system_property_get("vendor.hwc.r800.overlay", v);
	return !strcmp(v, "1");
}

/* DECON window parameters for a layer, or -1 if it cannot be an overlay. */
static int ovl_layer(struct r800_hwc *h, hwc_layer_1_t *l, struct r800_win_config *c)
{
	const native_handle_t *nh = (const native_handle_t *)l->handle;
	const hwc_rect_t *df = &l->displayFrame;
	int sw, sh, dw, dh;
	int stride, fmt, dfmt, blend;

	if (l->compositionType != HWC_FRAMEBUFFER && l->compositionType != HWC_OVERLAY)
		return -1;
	if ((l->flags & HWC_SKIP_LAYER) || l->transform || !l->handle || !handle_ok(l->handle) ||
	    nh->numFds < 1 || nh->data[0] < 0)
		return -1;
	/* Validate float and rectangle bounds before integer conversion. */
	if (df->left < 0 || df->top < 0 || df->right <= df->left || df->bottom <= df->top ||
	    df->right > (int)h->var.xres || df->bottom > (int)h->var.yres)
		return -1;
	dw = df->right - df->left;
	dh = df->bottom - df->top;
	if (!isfinite(l->sourceCropf.left) || !isfinite(l->sourceCropf.top) ||
	    !isfinite(l->sourceCropf.right) || !isfinite(l->sourceCropf.bottom) ||
	    l->sourceCropf.left != 0 || l->sourceCropf.top != 0 ||
	    l->sourceCropf.right != (float)dw || l->sourceCropf.bottom != (float)dh ||
	    dw < 16)
		return -1;
	sw = dw;
	sh = dh;
	if (checked_buffer(h, l->handle, sw, sh, &stride, &fmt))
		return -1;
	switch (fmt) {
	case HAL_PIXEL_FORMAT_RGBA_8888: dfmt = 2; break;   /* DECON_PIXEL_FORMAT_RGBA_8888 */
	case HAL_PIXEL_FORMAT_RGBX_8888: dfmt = 6; break;   /* RGBX_8888 */
	case HAL_PIXEL_FORMAT_BGRA_8888: dfmt = 3; break;   /* BGRA_8888 */
	default: return -1;
	}
	switch (l->blending) {
	case HWC_BLENDING_NONE:     blend = 0; break;
	case HWC_BLENDING_PREMULT:  blend = 1; break;
	case HWC_BLENDING_COVERAGE: blend = 2; break;
	default: return -1;
	}
	if (c) {
		c->state = R800_WIN_STATE_BUFFER;
		c->fd_idma[0] = nh->data[0];
		c->acq_fence = l->acquireFenceFd;
		c->plane_alpha = l->planeAlpha;
		c->blending = blend;
		c->format = dfmt;
		c->src = (struct r800_frame){ 0, 0, (uint32_t)sw, (uint32_t)sh, (uint32_t)stride, (uint32_t)sh };
		c->dst = (struct r800_frame){ df->left, df->top, (uint32_t)dw, (uint32_t)dh, h->var.xres, h->var.yres };
	}
	return 0;
}

/* Present the overlay layers prepare() picked. 0 on success (fences filled). */
static int ovl_present(struct r800_hwc *h, hwc_display_contents_1_t *c, int *retire)
{
	struct r800_win_config_data d;
	int w;

	memset(&d, 0, sizeof(d));
	d.retire_fence = -1;
	d.fd_odma = -1;
	for (w = 0; w <= R800_MAX_DECON_WIN; w++) {
		d.config[w].state = R800_WIN_STATE_DISABLED;
		d.config[w].fd_idma[0] = d.config[w].fd_idma[1] = d.config[w].fd_idma[2] = -1;
		d.config[w].acq_fence = d.config[w].rel_fence = -1;
	}
	for (w = 0; w < h->ovl_n; w++) {
		if (ovl_layer(h, LAYER(c, h->ovl_idx[w]), &d.config[w]))
			return -1;
		d.config[w].channel = (uint32_t)w;
	}
	if (ioctl(h->fb_fd, R800_S3CFB_WIN_CONFIG, &d)) {
		int e = errno;
		if (h->ovl_fail++ < 10 || (h->ovl_fail % 600) == 0)
			LOGE("overlay WIN_CONFIG (%d layers) failed: %s (%lu)", h->ovl_n, strerror(e), h->ovl_fail);
		if (h->ovl_fail >= 5) {
			LOGE("overlays disabled after %lu failures: GPU composition only", h->ovl_fail);
			h->ovl_off = 1;
		}
		return -1;
	}
	for (w = 0; w < h->ovl_n; w++) {
		hwc_layer_1_t *l = LAYER(c, h->ovl_idx[w]);
		if (l->acquireFenceFd >= 0)
			close(l->acquireFenceFd);
		l->acquireFenceFd = -1;
		/* Transfer the kernel-created release FD directly. In the pinned
		 * command-mode driver it refers to the same sync_file as retire,
		 * but is a separately owned descriptor. Do not close and re-dup. */
		l->releaseFenceFd = d.config[w].rel_fence;
		d.config[w].rel_fence = -1;
		if (l->releaseFenceFd < 0 && d.retire_fence >= 0) {
			/* Compatibility with older driver/off-state responses.
			 * Missing release on an accepted update is exceptional. */
			l->releaseFenceFd = fcntl(d.retire_fence, F_DUPFD_CLOEXEC, 0);
			if (l->releaseFenceFd < 0) {
				LOGE("missing release fence and retire dup failed; disable overlays");
				h->ovl_off = 1;
			}
		}
		if (l->releaseFenceFd < 0 && d.retire_fence < 0) {
			LOGE("missing release and retire fences; disable overlays");
			h->ovl_off = 1;
		}
	}
	*retire = d.retire_fence;
	if (h->ovl_frames++ < 3 || (h->ovl_frames % 1800) == 0)
		LOGI("overlay frame %lu: %d layers (gpu frames %lu)", h->ovl_frames, h->ovl_n, h->gpu_frames);
	return 0;
}

/* ---- HWC 1.1 entry points ---- */
static int r800_prepare(hwc_composer_device_1_t *dev, size_t n, hwc_display_contents_1_t **displays)
{
	struct r800_hwc *h = (struct r800_hwc *)dev;
	size_t i;
	int nl = 0, ok;
	pthread_mutex_lock(&h->doze_lock);
	h->ovl_n = 0;
	if (validate_displays(h, n, displays)) {
		LOGE("prepare: incompatible layer list (stride %zu)", h->layer_stride);
		pthread_mutex_unlock(&h->doze_lock);
		return -EINVAL;
	}
	if (n < 1 || !displays[0]) {
		pthread_mutex_unlock(&h->doze_lock);
		return 0;
	}
	h->no_buffer = 0;
	ok = !h->power_unknown && ovl_enabled(h);
	for (i = 0; i < displays[0]->numHwLayers; i++) {
		hwc_layer_1_t *l = LAYER(displays[0], i);
		if ((l->compositionType == HWC_BACKGROUND || l->compositionType == HWC_SIDEBAND) && i < 64)
			h->no_buffer |= 1ULL << i;
		if (l->compositionType == HWC_FRAMEBUFFER_TARGET)
			continue;
		if (ok && (nl >= R800_MAX_DECON_WIN || ovl_layer(h, l, NULL)))
			ok = 0;
		else if (ok)
			h->ovl_idx[nl++] = i;
	}
	h->ovl_n = ok ? nl : 0;
	for (i = 0; i < displays[0]->numHwLayers; i++) {
		hwc_layer_1_t *l = LAYER(displays[0], i);
		if (l->compositionType != HWC_FRAMEBUFFER_TARGET)
			l->compositionType = h->ovl_n ? HWC_OVERLAY : HWC_FRAMEBUFFER;
	}
	if (!h->ovl_n)
		h->gpu_frames++;
	pthread_mutex_unlock(&h->doze_lock);
	return 0;
}

static int doze_resume_locked(struct r800_hwc *h);
static int64_t mono_ns(void);

static int r800_set(hwc_composer_device_1_t *dev, size_t n, hwc_display_contents_1_t **displays)
{
	struct r800_hwc *h = (struct r800_hwc *)dev;
	size_t d, i;

	int power_ret;
	int present_ok;
	pthread_mutex_lock(&h->doze_lock);
	if (validate_displays(h, n, displays)) {
		h->ovl_n = 0;
		LOGE("set: incompatible layer list (stride %zu); not touching FDs", h->layer_stride);
		pthread_mutex_unlock(&h->doze_lock);
		return -EINVAL;
	}
	power_ret = doze_resume_locked(h);
	present_ok = !power_ret && !h->blanked && !h->power_unknown && !h->doze_susp;

	static int calls;
	/* setprop debug.r800.dumplayers N: log the next N frames' layer lists */
	if ((calls % 60) == 0) {
		char v[PROP_VALUE_MAX] = "";
		__system_property_get("debug.r800.dumplayers", v);
		h->dump_left = atoi(v) > 0 && atoi(v) != h->dump_seen ? atoi(v) : h->dump_left;
		if (atoi(v) > 0)
			h->dump_seen = atoi(v);
		v[0] = 0;
		__system_property_get("debug.r800.fencescan", v);
		if (atoi(v) != h->fencescan_seen) {
			h->fencescan_seen = atoi(v);
			fence_scan();
		}
	}
	if (h->dump_left > 0 && n > 0 && displays[0]) {
		size_t j;
		h->dump_left--;
		LOGE("frame %d: %zu layers flags 0x%x", calls, displays[0]->numHwLayers, displays[0]->flags);
		for (j = 0; j < displays[0]->numHwLayers; j++) {
			hwc_layer_1_t *L = LAYER(displays[0], j);
			LOGE("  L%zu type %d flags 0x%x handle %p acq %d blend 0x%x alpha %u disp %d,%d-%d,%d crop %.0f,%.0f-%.0f,%.0f",
			     j, L->compositionType, L->flags, (void *)L->handle, L->acquireFenceFd, L->blending,
			     L->planeAlpha, L->displayFrame.left, L->displayFrame.top, L->displayFrame.right,
			     L->displayFrame.bottom, L->sourceCropf.left, L->sourceCropf.top, L->sourceCropf.right,
			     L->sourceCropf.bottom);
		}
	}
	if (calls++ < 3) {
		size_t k;
		LOGI("set #%d: numDisplays=%zu fb_mem=%p gralloc=%p blanked=%d", calls, n, h->fb_mem,
		     (void *)h->gralloc, h->blanked);
		for (k = 0; displays && k < n && displays[k] && k < 1; k++) {
			size_t j;
			for (j = 0; j < displays[k]->numHwLayers; j++)
				LOGI("  disp %zu layer %zu type %d handle %p acq %d", k, j,
				     LAYER(displays[k], j)->compositionType,
				     (void *)LAYER(displays[k], j)->handle, LAYER(displays[k], j)->acquireFenceFd);
		}
	}
	int presented = 0;

	for (d = 0; d < n; d++) {
		hwc_display_contents_1_t *c = displays[d];
		int retire = -1;

		if (!c)
			continue;
		/* This HAL does not render virtual displays; consume their input fence. */
		if (d == HWC_DISPLAY_VIRTUAL && c->outbufAcquireFenceFd >= 0) {
			close(c->outbufAcquireFenceFd);
			c->outbufAcquireFenceFd = -1;
		}
		if (d == 0 && h->ovl_n > 0) {
			/* prepare() marked these layers HWC_OVERLAY: nothing was composed
			 * into the FB target. On failure the previous frame stays up. */
			int w, valid = h->ovl_n <= R800_MAX_DECON_WIN;
			for (w = 0; valid && w < h->ovl_n; w++) {
				if (h->ovl_idx[w] >= c->numHwLayers ||
				    LAYER(c, h->ovl_idx[w])->compositionType != HWC_OVERLAY)
					valid = 0;
				for (int prev = 0; valid && prev < w; prev++)
					if (h->ovl_idx[prev] == h->ovl_idx[w])
						valid = 0;
			}
			/* Every overlay must be selected exactly once. */
			size_t overlays = 0;
			for (i = 0; i < c->numHwLayers; i++)
				if (LAYER(c, i)->compositionType == HWC_OVERLAY)
					overlays++;
			if (!valid || overlays != (size_t)h->ovl_n) {
				h->ovl_off = 1;
				h->ovl_n = 0;
				for (i = 0; i < c->numHwLayers; i++) {
					hwc_layer_1_t *l = LAYER(c, i);
					if (l->acquireFenceFd >= 0)
						close(l->acquireFenceFd);
					l->acquireFenceFd = l->releaseFenceFd = -1;
				}
				c->retireFenceFd = -1;
				continue;
			}
			int ok = present_ok && h->power_mode == HWC_POWER_MODE_NORMAL && ovl_present(h, c, &retire) == 0;
			if (ok)
				presented = 1;
			for (w = 0; w < h->ovl_n; w++) {
				hwc_layer_1_t *l = LAYER(c, h->ovl_idx[w]);
				if (!ok) {
					if (l->acquireFenceFd >= 0)
						close(l->acquireFenceFd);
					l->acquireFenceFd = -1;
					l->releaseFenceFd = -1;
				}
			}
			for (i = 0; i < c->numHwLayers; i++) {
				hwc_layer_1_t *l = LAYER(c, i);
				if (l->compositionType == HWC_OVERLAY)
					continue;          /* fences done above */
				if (l->acquireFenceFd >= 0)
					close(l->acquireFenceFd);
				l->acquireFenceFd = -1;
				l->releaseFenceFd = -1;
			}
			c->retireFenceFd = retire;
			continue;
		}
		for (i = 0; i < c->numHwLayers; i++) {
			hwc_layer_1_t *l = LAYER(c, i);
			l->releaseFenceFd = -1;
			if (d == 0 && l->compositionType == HWC_FRAMEBUFFER_TARGET) {
				if (present_ok && h->zerocopy && wc_present(h, l, &retire) == 0) {
					presented = 1;
					continue;
				}
				/* A failed acquire fence is never permission to read the buffer. */
				int ready = wait_fence(l->acquireFenceFd);
				l->acquireFenceFd = -1;
				if (ready) {
					LOGW("skip frame: acquire fence failed (%d)", ready);
				} else if (present_ok && fb_present(h, l->handle, 1) == 0) {
					presented = 1;
				}
			} else if (l->acquireFenceFd >= 0) {
				close(l->acquireFenceFd);
				l->acquireFenceFd = -1;
			}
		}
		/* No client target: do not access a layer whose fence was consumed. */
		/* no usable layer: keep the last frame (was an orange debug fill) */
		c->retireFenceFd = retire;
	}
	if (presented) {
		h->last_present_ns = mono_ns();
		pthread_cond_signal(&h->doze_cond);
	}
	pthread_mutex_unlock(&h->doze_lock);
	return power_ret;
}

/*
 * Vsync. The panel is a DSI command-mode panel: DECON timestamps its TE
 * interrupt in decon->vsync.timestamp and, while S3CFB_SET_VSYNC_INT is on,
 * signals the "vsync" sysfs node (POLLPRI) on every TE. Those are the real
 * refresh times. When DECON hibernates (nothing to show) TE stops, so we
 * fill in timer vsyncs on the grid of the last real one: SurfaceFlinger keeps
 * a steady model and the next real TE lands where it expects it. A free
 * running 60 Hz timer (the old scheme) drifts against the panel and makes
 * frames miss their slot.
 */
#define R800_S3CFB_SET_VSYNC_INT _IOW('F', 206, uint32_t)
#define R800_S3CFB_POWER_MODE _IOW('F', 223, uint32_t)
#define R800_DISP_PWR_DOZE 1
#define R800_DISP_PWR_DOZE_SUSPEND 3
#define R800_VSYNC_NODE "/sys/devices/platform/148b0000.decon_f/vsync"

static int64_t mono_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

/* Reject malformed, future and stale timestamps before using a TE grid. */
static int64_t parse_hw_vsync(const char *buf, int64_t now)
{
	char *end;
	int64_t value;
	if (!isdigit((unsigned char)buf[0]))
		return 0;
	errno = 0;
	value = strtoll(buf, &end, 10);
	if (errno || end == buf || value <= 0 || value > now ||
	    now - value > 2000000000LL)
		return 0;
	while (isspace((unsigned char)*end))
		end++;
	return *end ? 0 : value;
}

static int64_t read_hw_vsync(int fd)
{
	char buf[32];
	ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
	if (n <= 0 || n == sizeof(buf) - 1 || memchr(buf, 0, n))
		return 0;
	buf[n] = 0;
	return parse_hw_vsync(buf, mono_ns());
}

static int64_t next_timer_vsync(int64_t now, int64_t last_hw, int64_t last_sent)
{
	int64_t base = last_hw, threshold = now;
	if (base <= 0 || base > now || now - base > 2000000000LL)
		base = now;
	if (last_sent > 0 && last_sent <= now &&
	    last_sent + VSYNC_PERIOD_NS / 2 > threshold)
		threshold = last_sent + VSYNC_PERIOD_NS / 2;
	return base + ((threshold - base) / VSYNC_PERIOD_NS + 1) * VSYNC_PERIOD_NS;
}

/* Re-open failed TE nodes at a bounded cadence, never on every frame. */
#define R800_TE_RETRY_NS 2000000000LL
#define R800_TE_BAD_LIMIT 8

static int te_poll_lost(int pr, short revents, int err)
{
	return (pr > 0 && (revents & (POLLHUP | POLLNVAL))) ||
	       (pr < 0 && err != EINTR);
}

static int te_retry_due(int fd, int64_t now, int64_t retry_at)
{
	return fd < 0 && now >= retry_at;
}

/* The HWC1 ABI guarantees that vsync() does not call back into HAL hooks.
 * Pin the registration until dispatch completes, without holding lock
 * during framework code. Pending replacements block new acquisitions. */
static const hwc_procs_t *r800_callback_acquire(struct r800_hwc *h,
					      unsigned long epoch)
{
	const hwc_procs_t *procs = NULL;
	pthread_mutex_lock(&h->lock);
	if (!h->vsync_stop && h->vsync_enabled && h->vsync_epoch == epoch &&
	    !h->callback_waiters && h->procs && h->procs->vsync) {
		procs = h->procs;
		h->callback_active++;
	}
	pthread_mutex_unlock(&h->lock);
	return procs;
}

static void r800_callback_release(struct r800_hwc *h)
{
	pthread_mutex_lock(&h->lock);
	if (--h->callback_active == 0)
		pthread_cond_broadcast(&h->cond);
	pthread_mutex_unlock(&h->lock);
}

static void r800_callback_replace(struct r800_hwc *h, const hwc_procs_t *procs)
{
	pthread_mutex_lock(&h->lock);
	/* Defensive handling of a contract-violating reentrant registration:
	 * the currently executing callback must remain valid until it returns. */
	if (h->callback_active && h->vsync_started &&
	    pthread_equal(pthread_self(), h->vsync_thread)) {
		if (!h->vsync_stop) {
			h->procs = procs;
			h->vsync_epoch++;
		}
		pthread_mutex_unlock(&h->lock);
		return;
	}
	h->callback_waiters++;
	while (h->callback_active)
		pthread_cond_wait(&h->cond, &h->lock);
	if (!h->vsync_stop) {
		h->procs = procs;
		h->vsync_epoch++;
	}
	h->callback_waiters--;
	pthread_cond_broadcast(&h->cond);
	pthread_mutex_unlock(&h->lock);
}

static void *vsync_loop(void *arg)
{
	struct r800_hwc *h = arg;
	int vfd = -1;
	int bad_events = 0;
	int64_t retry_at = 0, last_hw = 0, last_sent = 0;
	unsigned long hw_count = 0, sw_count = 0, seen_epoch = 0;

	for (;;) {
		int64_t ts = 0, now;
		unsigned long epoch;
		const hwc_procs_t *procs = NULL;

		pthread_mutex_lock(&h->lock);
		while (!h->vsync_enabled && !h->vsync_stop)
			pthread_cond_wait(&h->cond, &h->lock);
		if (h->vsync_stop) {
			pthread_mutex_unlock(&h->lock);
			break;
		}
		epoch = h->vsync_epoch;
		pthread_mutex_unlock(&h->lock);
		if (epoch != seen_epoch) {
			/* Do not reuse a pre-disable timestamp or pending IRQ. */
			last_hw = vfd >= 0 ? read_hw_vsync(vfd) : 0;
			seen_epoch = epoch;
			bad_events = 0;
		}

		now = mono_ns();
		if (te_retry_due(vfd, now, retry_at)) {
			retry_at = now + R800_TE_RETRY_NS;
			vfd = open(R800_VSYNC_NODE, O_RDONLY | O_CLOEXEC);
			if (vfd >= 0) {
				last_hw = read_hw_vsync(vfd); /* baseline, not a callback */
				bad_events = 0;
				LOGI("vsync: TE node opened");
			}
		}
		if (vfd >= 0) {
			struct pollfd p = { .fd = vfd, .events = POLLPRI | POLLERR };
			int pr = poll(&p, 1, 22);
			int err = pr < 0 ? errno : 0;
			int lost = te_poll_lost(pr, p.revents, err);
			if (!lost && pr > 0 && (p.revents & POLLPRI)) {
				int64_t hw = read_hw_vsync(vfd);
				if (hw > last_hw) {
					last_hw = hw;
					bad_events = 0;
					if (hw > last_sent + VSYNC_PERIOD_NS / 2)
						ts = hw;
				} else {
					bad_events++;
				}
			} else if (!lost && pr > 0 && (p.revents & POLLERR)) {
				bad_events++;
			} else if (pr == 0) {
				/* No TE while idle is normal, not a source failure. */
				bad_events = 0;
			}
			if (lost || bad_events >= R800_TE_BAD_LIMIT) {
				close(vfd);
				vfd = -1;
				last_hw = 0;
				bad_events = 0;
				retry_at = mono_ns() + R800_TE_RETRY_NS;
				LOGW("vsync: TE source lost; timer fallback and retry");
			}
		}

		if (ts) {
			hw_count++;
		} else {
			/* A repeated/malformed TE or POLLERR must not starve callbacks. */
			int rc;
			now = mono_ns();
			ts = next_timer_vsync(now, last_hw, last_sent);
			struct timespec t = { (time_t)(ts / 1000000000LL), (long)(ts % 1000000000LL) };
			do {
				rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t, NULL);
			} while (rc == EINTR);
			if (rc) {
				LOGE("vsync timer failed: %s", strerror(rc));
				usleep(16000);
				continue;
			}
			sw_count++;
		}

		if (ts > last_sent)
			procs = r800_callback_acquire(h, epoch);
		if (procs) {
			last_sent = ts;
			procs->vsync(procs, 0, ts);
			r800_callback_release(h);
		}
		if (((hw_count + sw_count) & 1023) == 0)
			LOGI("vsync: %lu from TE, %lu filled in", hw_count, sw_count);
	}
	if (vfd >= 0)
		close(vfd);
	return NULL;
}

static int r800_event_control(hwc_composer_device_1_t *dev, int disp, int event, int enabled)
{
	struct r800_hwc *h = (struct r800_hwc *)dev;
	uint32_t on = !!enabled;
	if (disp != 0 || event != HWC_EVENT_VSYNC)
		return -EINVAL;
	pthread_mutex_lock(&h->lock);
	if (h->vsync_stop) {
		pthread_mutex_unlock(&h->lock);
		return -ESHUTDOWN;
	}
	if (h->vsync_enabled != (int)on) {
		h->vsync_epoch++;
		int r = h->fb_fd >= 0 ? ioctl(h->fb_fd, R800_S3CFB_SET_VSYNC_INT, &on) : -1;
		static unsigned long toggles;
		if (toggles++ < 40)
			LOGI("vsync %s (decon vsync int: %s)", on ? "on" : "off",
			     r ? strerror(errno) : "ok");
	}
	h->vsync_enabled = on;
	pthread_cond_signal(&h->cond);
	pthread_mutex_unlock(&h->lock);
	return 0;
}

/* All display power transitions and frame submissions hold doze_lock. */
static int r800_blank(hwc_composer_device_1_t *dev, int disp, int blank)
{
	struct r800_hwc *h = (struct r800_hwc *)dev;
	static const char *node = "/sys/devices/platform/148e0000.dsim/cmd_rw";
	char v[PROP_VALUE_MAX] = "";
	int fd, ret;
	ssize_t written;

	if (disp != 0)
		return -EINVAL;
	blank = !!blank;
	if (blank == h->blanked && !h->power_unknown)
		return 0;
	__system_property_get("debug.r800.realblank", v);
	/* Do not accept the kernel's keep-panel-on no-op as a real blank. */
	if (h->real_blanked || (blank && !strcmp(v, "1"))) {
		if (ioctl(h->fb_fd, FBIOBLANK, blank ? FB_BLANK_POWERDOWN : FB_BLANK_UNBLANK))
			return -errno;
		h->real_blanked = blank;
		h->blanked = blank;
		return 0;
	}
	fd = open(node, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	do {
		written = write(fd, blank ? "3" : "2", 1);
	} while (written < 0 && errno == EINTR);
	ret = written == 1 ? 0 : (written < 0 ? -errno : -EIO);
	close(fd);
	if (ret)
		return ret;
	h->blanked = blank;
	return 0;
}

/* Automatic DECON power-down is experimental; normal ambient stays in DOZE. */
static int doze_idle_ms(void)
{
	char v[PROP_VALUE_MAX] = "";
	char *end;
	long ms;
	__system_property_get("vendor.hwc.r800.doze_idle_ms", v);
	if (!v[0])
		return 0;
	ms = strtol(v, &end, 10);
	return *end || ms < 100 || ms > 60000 ? 0 : (int)ms;
}

static int doze_resume_locked(struct r800_hwc *h)
{
	uint32_t pwr = R800_DISP_PWR_DOZE;
	if (h->power_unknown)
		return -EIO;
	if (h->doze_susp && h->power_mode == HWC_POWER_MODE_DOZE) {
		if (ioctl(h->fb_fd, R800_S3CFB_POWER_MODE, &pwr)) {
			int ret = -errno;
			LOGE("doze resume failed: %s", strerror(-ret));
			h->power_unknown = 1;
			return ret;
		}
		h->doze_susp = 0;
	}
	return 0;
}

static void *doze_idle_loop(void *arg)
{
	struct r800_hwc *h = arg;
	pthread_mutex_lock(&h->doze_lock);
	for (;;) {
		int ms;
		int64_t due, now;
		struct timespec t;
		while (!h->idle_stop && (h->power_unknown || h->power_mode != HWC_POWER_MODE_DOZE || h->doze_susp))
			pthread_cond_wait(&h->doze_cond, &h->doze_lock);
		if (h->idle_stop)
			break;
		ms = doze_idle_ms();
		now = mono_ns();
		due = ms ? h->last_present_ns + (int64_t)ms * 1000000LL : now + 5000000000LL;
		if (!ms || now < due) {
			t.tv_sec = due / 1000000000LL;
			t.tv_nsec = due % 1000000000LL;
			pthread_cond_timedwait(&h->doze_cond, &h->doze_lock, &t);
			continue;
		}
		uint32_t pwr = R800_DISP_PWR_DOZE_SUSPEND;
		if (ioctl(h->fb_fd, R800_S3CFB_POWER_MODE, &pwr)) {
			LOGE("doze suspend failed: %s", strerror(errno));
			h->power_unknown = 1;
			continue;
		}
		h->doze_susp = 1;
		h->doze_suspends++;
	}
	pthread_mutex_unlock(&h->doze_lock);
	return NULL;
}

static int r800_set_power_mode(hwc_composer_device_1_t *dev, int disp, int mode)
{
	struct r800_hwc *h = (struct r800_hwc *)dev;
	int prev, r = 0, suspended = 0;
	uint32_t pwr;

	if (disp != 0 || (mode != HWC_POWER_MODE_OFF && mode != HWC_POWER_MODE_NORMAL &&
	    mode != HWC_POWER_MODE_DOZE && mode != HWC_POWER_MODE_DOZE_SUSPEND))
		return -EINVAL;
	pthread_mutex_lock(&h->doze_lock);
	prev = h->power_mode;
	LOGI("setPowerMode %d -> %d", prev, mode);
	/* A doze/unknown state requires explicit DECON resume before DCS. */
	if (h->power_unknown || prev == HWC_POWER_MODE_DOZE || prev == HWC_POWER_MODE_DOZE_SUSPEND) {
		if (ioctl(h->fb_fd, FBIOBLANK, FB_BLANK_UNBLANK)) {
			r = -errno;
			goto failed;
		}
		h->real_blanked = 0;
		h->blanked = 0;
		h->power_unknown = 1; /* until requested transition completes */
	}
	switch (mode) {
	case HWC_POWER_MODE_OFF:
		r = r800_blank(dev, disp, 1);
		break;
	case HWC_POWER_MODE_NORMAL:
		r = r800_blank(dev, disp, 0);
		break;
	case HWC_POWER_MODE_DOZE:
	case HWC_POWER_MODE_DOZE_SUSPEND:
		r = r800_blank(dev, disp, 0);
		if (r)
			break;
		/* Keep the panel in DOZE when automatic suspend is not opted in. */
		suspended = mode == HWC_POWER_MODE_DOZE_SUSPEND && doze_idle_ms() > 0;
		pwr = suspended ? R800_DISP_PWR_DOZE_SUSPEND : R800_DISP_PWR_DOZE;
		if (ioctl(h->fb_fd, R800_S3CFB_POWER_MODE, &pwr))
			r = -errno;
		break;
	}
	if (r)
		goto failed;
	h->doze_susp = suspended;
	h->power_mode = mode;
	h->power_unknown = 0;
	h->last_present_ns = mono_ns();
	pthread_cond_signal(&h->doze_cond);
	pthread_mutex_unlock(&h->doze_lock);
	return 0;
failed:
	h->power_unknown = 1;
	LOGE("setPowerMode %d failed: %s", mode, strerror(-r));
	pthread_cond_signal(&h->doze_cond);
	pthread_mutex_unlock(&h->doze_lock);
	return r;
}

static int r800_get_active_config(hwc_composer_device_1_t *dev, int disp)
{
	(void)dev;
	return disp == 0 ? 0 : -1;
}

static int r800_set_active_config(hwc_composer_device_1_t *dev, int disp, int index)
{
	(void)dev;
	return disp == 0 && index == 0 ? 0 : -EINVAL;
}

static int r800_query(hwc_composer_device_1_t *dev, int what, int *value)
{
	(void)dev;
	switch (what) {
	case HWC_BACKGROUND_LAYER_SUPPORTED: *value = 0; return 0;
	case HWC_VSYNC_PERIOD:               *value = (int)VSYNC_PERIOD_NS; return 0;
	case HWC_DISPLAY_TYPES_SUPPORTED:    *value = HWC_DISPLAY_PRIMARY_BIT; return 0;
	default:                             return -EINVAL;
	}
}

static void r800_register_procs(hwc_composer_device_1_t *dev, hwc_procs_t const *procs)
{
	struct r800_hwc *h = (struct r800_hwc *)dev;
	r800_callback_replace(h, procs);
}

static int r800_get_display_configs(hwc_composer_device_1_t *dev, int disp, uint32_t *configs, size_t *num)
{
	(void)dev;
	if (disp != 0)
		return -EINVAL;
	if (*num > 0)
		configs[0] = 0;
	*num = 1;
	return 0;
}

static int r800_get_display_attributes(hwc_composer_device_1_t *dev, int disp, uint32_t config,
				       const uint32_t *attrs, int32_t *values)
{
	struct r800_hwc *h = (struct r800_hwc *)dev;
	/* 33 mm panel, 360 px -> ~277 dpi; HWC wants dpi * 1000 */
	int32_t dpi_x = h->var.width ? (int32_t)(h->var.xres * 25400LL / h->var.width) : 277000;
	int32_t dpi_y = h->var.height ? (int32_t)(h->var.yres * 25400LL / h->var.height) : 277000;
	int i;
	(void)config;
	if (disp != 0)
		return -EINVAL;
	for (i = 0; attrs[i] != HWC_DISPLAY_NO_ATTRIBUTE; i++) {
		switch (attrs[i]) {
		case HWC_DISPLAY_VSYNC_PERIOD: values[i] = (int32_t)VSYNC_PERIOD_NS; break;
		case HWC_DISPLAY_WIDTH:        values[i] = (int32_t)h->var.xres; break;
		case HWC_DISPLAY_HEIGHT:       values[i] = (int32_t)h->var.yres; break;
		case HWC_DISPLAY_DPI_X:        values[i] = dpi_x; break;
		case HWC_DISPLAY_DPI_Y:        values[i] = dpi_y; break;
		default:                       values[i] = 0; break;
		}
	}
	return 0;
}

static void r800_dump(hwc_composer_device_1_t *dev, char *buf, int len)
{
	struct r800_hwc *h = (struct r800_hwc *)dev;
	snprintf(buf, len, "hwc-r800: %ux%u frames=%lu vsync=%d blanked=%d overlay frames=%lu gpu=%lu fail=%lu fmt=%d off=%d\n",
		 h->var.xres, h->var.yres, h->frames, h->vsync_enabled, h->blanked, h->ovl_frames,
		 h->gpu_frames, h->ovl_fail, h->fmt_verified, h->ovl_off);
}

/* Framework must quiesce external HAL entrypoints before close. Signal
 * both workers, join without holding either mutex, and only then free.
 * A callback cannot close its own worker; do not attempt self-join. */
static int r800_stop_workers(struct r800_hwc *h)
{
	int r;
	uint32_t off = 0;
	if ((h->vsync_started && pthread_equal(pthread_self(), h->vsync_thread)) ||
	    (h->idle_started && pthread_equal(pthread_self(), h->idle_thread)))
		return -EDEADLK;

	pthread_mutex_lock(&h->lock);
	h->vsync_stop = 1;
	h->vsync_epoch++;
	h->procs = NULL;
	if (h->vsync_enabled && h->fb_fd >= 0 &&
	    ioctl(h->fb_fd, R800_S3CFB_SET_VSYNC_INT, &off))
		LOGW("vsync interrupt disable failed: %s", strerror(errno));
	h->vsync_enabled = 0;
	pthread_cond_broadcast(&h->cond);
	pthread_mutex_unlock(&h->lock);

	pthread_mutex_lock(&h->doze_lock);
	h->idle_stop = 1;
	pthread_cond_broadcast(&h->doze_cond);
	pthread_mutex_unlock(&h->doze_lock);

	if (h->vsync_started) {
		r = pthread_join(h->vsync_thread, NULL);
		if (r)
			return -r;
		h->vsync_started = 0;
	}
	if (h->idle_started) {
		r = pthread_join(h->idle_thread, NULL);
		if (r)
			return -r;
		h->idle_started = 0;
	}
	return 0;
}

static void r800_release(struct r800_hwc *h)
{
	if (h->fb_mem)
		munmap(h->fb_mem, h->fix.smem_len);
	if (h->fb_fd >= 0)
		close(h->fb_fd);
	if (h->hardware_lib)
		dlclose(h->hardware_lib);
	pthread_cond_destroy(&h->doze_cond);
	pthread_mutex_destroy(&h->doze_lock);
	pthread_cond_destroy(&h->cond);
	pthread_mutex_destroy(&h->lock);
	free(h);
}

static int r800_close(hw_device_t *dev)
{
	struct r800_hwc *h = (struct r800_hwc *)dev;
	int r;
	if (!h)
		return -EINVAL;
	r = r800_stop_workers(h);
	if (r)
		return r; /* never free storage while a worker may still use it */
	r800_release(h);
	return 0;
}

static int r800_open(const hw_module_t *module, const char *name, hw_device_t **device)
{
	struct r800_hwc *h;
	pthread_condattr_t doze_attr;
	int r;

	if (!device)
		return -EINVAL;
	*device = NULL;
	if (!module || !name || strcmp(name, HWC_HARDWARE_COMPOSER))
		return -EINVAL;
	char stride_prop[PROP_VALUE_MAX] = "";
	__system_property_get("debug.r800.layer_stride", stride_prop);
	size_t stride = select_layer_stride(stride_prop);
	if (!stride) {
		LOGE("unsupported layer_stride property");
		return -EINVAL;
	}
	h = calloc(1, sizeof(*h));
	if (!h)
		return -ENOMEM;
	h->fb_fd = -1;
	h->layer_stride = stride;
	LOGI("fixed HWC layer stride %zu", stride);
	if ((r = pthread_mutex_init(&h->lock, NULL)))
		goto fail_alloc;
	if ((r = pthread_cond_init(&h->cond, NULL)))
		goto fail_lock;
	if ((r = pthread_mutex_init(&h->doze_lock, NULL)))
		goto fail_cond;
	if ((r = pthread_condattr_init(&doze_attr)))
		goto fail_doze_lock;
	if (!(r = pthread_condattr_setclock(&doze_attr, CLOCK_MONOTONIC)))
		r = pthread_cond_init(&h->doze_cond, &doze_attr);
	pthread_condattr_destroy(&doze_attr);
	if (r)
		goto fail_doze_lock;

	h->power_mode = HWC_POWER_MODE_NORMAL;   /* the panel is on at start */
	h->base.common.tag = HARDWARE_DEVICE_TAG;
	h->base.common.version = HWC_DEVICE_API_VERSION_1_4;
	h->base.common.module = (hw_module_t *)module;
	h->base.common.close = r800_close;
	h->base.prepare = r800_prepare;
	h->base.set = r800_set;
	h->base.eventControl = r800_event_control;
	h->base.setPowerMode = r800_set_power_mode;   /* 1.4: replaces blank() */
	h->base.getActiveConfig = r800_get_active_config;
	h->base.setActiveConfig = r800_set_active_config;
	h->base.query = r800_query;
	h->base.registerProcs = r800_register_procs;
	h->base.dump = r800_dump;
	h->base.getDisplayConfigs = r800_get_display_configs;
	h->base.getDisplayAttributes = r800_get_display_attributes;

	r = fb_open(h);
	if (r) {
		LOGE("framebuffer unavailable (%d); HWC open refused", r);
		r800_release(h);
		return r;
	} else {
		LOGE("fb ok: %ux%u %ubpp smem=%u", h->var.xres, h->var.yres,
		     h->var.bits_per_pixel, h->fix.smem_len);
	}
	h->gralloc = load_gralloc(h);
	if (h->fb_mem) {
		/* The initramfs had fb0 open and released it at handover, which
		 * powers the panel down; unblank + re-apply the mode to wake it.
		 * Only on the first open after boot: on a composer restart DECON is
		 * still running (release keeps it on) and may be in window-config
		 * mode, and re-applying the mode there is the suspect for the
		 * restart hang. The property survives composer restarts. */
		char woke[PROP_VALUE_MAX] = "";
		__system_property_get("debug.r800.hwc_woke", woke);
		if (woke[0] != '1') {
			h->var.activate = FB_ACTIVATE_NOW;
			if (ioctl(h->fb_fd, FBIOPUT_VSCREENINFO, &h->var) ||
			    ioctl(h->fb_fd, FBIOBLANK, FB_BLANK_UNBLANK)) {
				h->power_unknown = 1;
				LOGE("initial panel wake failed: %s", strerror(errno));
			} else if (__system_property_set("debug.r800.hwc_woke", "1")) {
				LOGE("could not set debug.r800.hwc_woke");
			}
		} else {
			/* Retain the last frame, but require an explicit power transition. */
			h->power_unknown = 1;
			LOGE("composer restart: DECON left as is (no mode re-apply/unblank)");
		}
		/* no bring-up paint: after a composer restart the last frame stays */
	}
	/* Publish startup state before the worker threads can read it. */
	r = pthread_create(&h->vsync_thread, NULL, vsync_loop, h);
	if (r) {
		r800_release(h);
		return -r;
	}
	h->vsync_started = 1;
	r = pthread_create(&h->idle_thread, NULL, doze_idle_loop, h);
	if (r) {
		int stop = r800_stop_workers(h);
		if (!stop)
			r800_release(h);
		else
			LOGE("partial HWC open: worker join failed (%d); retaining state", stop);
		return -r;
	}
	h->idle_started = 1;
	*device = &h->base.common;
	LOGI("opened (HWC 1.4, DECON overlays for <=3 plain layers, else client composition -> DECON zero-copy)");
	return 0;

fail_doze_lock:
	pthread_mutex_destroy(&h->doze_lock);
fail_cond:
	pthread_cond_destroy(&h->cond);
fail_lock:
	pthread_mutex_destroy(&h->lock);
fail_alloc:
	free(h);
	return -r;
}

static struct hw_module_methods_t r800_methods = { .open = r800_open };

hwc_module_t HAL_MODULE_INFO_SYM = {
	.common = {
		.tag = HARDWARE_MODULE_TAG,
		.module_api_version = HWC_MODULE_API_VERSION_0_1,
		.hal_api_version = HARDWARE_HAL_API_VERSION,
		.id = HWC_HARDWARE_MODULE_ID,
		.name = "SM-R800 framebuffer hwcomposer",
		.author = "r800 bring-up",
		.methods = &r800_methods,
	},
};
