/*
 * lights.r800.so: legacy lights HAL for the SM-R800 Wear OS bring-up.
 *
 * Only the backlight is real. The kernel exposes it as
 * /sys/class/backlight/exynos_panel (0..255); the panel driver turns that
 * into Samsung AID/ELVSS commands. Loaded by vendor.samsung.hardware.light@2.0
 * through hw_get_module("lights") with ro.hardware.lights=r800.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <android/log.h>
#include <hardware/hardware.h>

#define LOG_TAG "lights-r800"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* from AOSP hardware/libhardware/include/hardware/lights.h (stable ABI) */
#define LIGHTS_HARDWARE_MODULE_ID "lights"
#define LIGHT_ID_BACKLIGHT "backlight"
struct light_state_t {
	unsigned int color;
	int flashMode;
	int flashOnMS;
	int flashOffMS;
	int brightnessMode;
};
struct light_device_t {
	struct hw_device_t common;
	int (*set_light)(struct light_device_t *dev, struct light_state_t const *state);
};

#define BACKLIGHT "/sys/class/backlight/exynos_panel/brightness"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_last = -1;

static int write_int(const char *path, int value)
{
	char buf[16];
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		int saved = errno;
		LOGE("open %s: %s", path, strerror(saved));
		return -saved;
	}
	int n = snprintf(buf, sizeof(buf), "%d\n", value);
	ssize_t written;
	do {
		written = write(fd, buf, n);
	} while (written < 0 && errno == EINTR);
	int ret = written < 0 ? -errno : written != n ? -EIO : 0;
	if (close(fd) && !ret)
		ret = -errno;
	return ret;
}

static int set_light_backlight(struct light_device_t *dev, struct light_state_t const *state)
{
	unsigned int c = state->color & 0x00ffffff;
	/* AOSP rgb_to_brightness */
	int br = ((77 * ((c >> 16) & 0xff)) + (150 * ((c >> 8) & 0xff)) + (29 * (c & 0xff))) >> 8;
	int ret = 0;

	(void)dev;
	pthread_mutex_lock(&g_lock);
	if (br != g_last) {
		ret = write_int(BACKLIGHT, br);
		if (!ret)
			g_last = br;
		LOGI("backlight %d (ret %d)", br, ret);
	}
	pthread_mutex_unlock(&g_lock);
	return ret;
}

static int close_lights(struct hw_device_t *dev)
{
	free(dev);
	return 0;
}

static int open_lights(const struct hw_module_t *module, const char *name, struct hw_device_t **device)
{
	struct light_device_t *dev;

	if (strcmp(name, LIGHT_ID_BACKLIGHT))
		return -EINVAL;   /* buttons, battery, notifications...: none on this watch */
	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return -ENOMEM;
	dev->common.tag = HARDWARE_DEVICE_TAG;
	dev->common.version = 0;
	dev->common.module = (struct hw_module_t *)module;
	dev->common.close = close_lights;
	dev->set_light = set_light_backlight;
	*device = &dev->common;
	LOGI("opened %s", name);
	return 0;
}

static struct hw_module_methods_t lights_module_methods = {
	.open = open_lights,
};

__attribute__((visibility("default")))
struct hw_module_t HAL_MODULE_INFO_SYM = {
	.tag = HARDWARE_MODULE_TAG,
	.version_major = 1,
	.version_minor = 0,
	.id = LIGHTS_HARDWARE_MODULE_ID,
	.name = "SM-R800 lights (exynos_panel backlight)",
	.author = "r800 bring-up",
	.methods = &lights_module_methods,
};
