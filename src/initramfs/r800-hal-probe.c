/* ARM32 Bionic diagnostic only. Lifecycle mode requires hardware-free guest. */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <hardware/audio.h>
#include <hardware/hwcomposer.h>
#include <hardware/hardware.h>
#include <stdio.h>
#include <string.h>

#if !defined(__BIONIC__) || !defined(__arm__) || __ANDROID_API__ != 28
#error "ARM32 Bionic API28 required"
#endif
_Static_assert(sizeof(hw_module_t) == 128, "Unexpected HAL module ABI");

static int missing(const char *path)
{
    return access(path, F_OK) == -1 && errno == ENOENT;
}

static int fd_count(void)
{
    int count = 0;
    for (int fd = 0; fd < 256; ++fd) {
        if (fcntl(fd, F_GETFD) != -1)
            ++count;
        else if (errno != EBADF)
            return -1;
    }
    return count;
}

static int lifecycle(const hw_module_t *module, const char *id)
{
    const char *name = NULL;
    int expected = 0;
    if (!strcmp(id, "audio")) name = AUDIO_HARDWARE_INTERFACE;
    else if (!strcmp(id, "gps")) name = "gps";
    else if (!strcmp(id, "lights")) name = "backlight";
    else if (!strcmp(id, "hwcomposer")) {
        name = HWC_HARDWARE_COMPOSER;
        expected = -ENOENT;
    } else if (!strcmp(id, "sensors")) {
        name = "poll";
        expected = -ENOENT;
    } else return 6;

    if (!missing("/dev/graphics/fb0") || !missing("/dev/fb0") ||
        !missing("/sys/class/sensors/ssp_sensor/enable") ||
        !missing("/dev/snd") || !missing("/dev/input")) {
        fprintf(stderr, "Hardware-free guest required\n");
        return 7;
    }
    int baseline = -1;
    /* Warm up logging before measuring descriptor count; no hardware I/O
     * methods, sensor polling, GPS init, PCM stream or brightness calls. */
    for (int i = 0; i < 17; ++i) {
        hw_device_t *device = NULL;
        int rc = module->methods->open(module, name, &device);
        if (rc != expected || (expected && device)) {
            fprintf(stderr, "open mismatch %s attempt=%d got=%d expected=%d\n",
                    id, i, rc, expected);
            return 8;
        }
        if (!expected) {
            if (!device || device->tag != HARDWARE_DEVICE_TAG ||
                device->module != module || !device->close)
                return 9;
            if (!strcmp(id, "audio")) {
                struct audio_hw_device *audio = (struct audio_hw_device *)device;
                bool mute = false;
                if (device->version != AUDIO_DEVICE_API_VERSION_2_0 ||
                    !audio->set_mic_mute || !audio->get_mic_mute ||
                    audio->set_mic_mute(audio, true) ||
                    audio->get_mic_mute(audio, &mute) || !mute ||
                    audio->set_mic_mute(audio, false) ||
                    audio->get_mic_mute(audio, &mute) || mute)
                    return 10;
            }
            if (device->close(device))
                return 11;
        }
        int now = fd_count();
        if (now < 0 || (i && now != baseline)) {
            fprintf(stderr, "descriptor count changed %s baseline=%d now=%d\n",
                    id, baseline, now);
            return 12;
        }
        baseline = now;
    }
    printf("HAL_LIFECYCLE_PASS %s repeats=16 open_rc=%d fd_window=256\n", id, expected);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3 && (argc != 4 || strcmp(argv[3], "--lifecycle"))) return 2;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 3;
    }
    dlerror();
    const hw_module_t *module = dlsym(handle, HAL_MODULE_INFO_SYM_AS_STR);
    const char *error = dlerror();
    if (error || !module || module->tag != HARDWARE_MODULE_TAG ||
        !module->id || strcmp(module->id, argv[2]) ||
        (module->hal_api_version != 0 && module->hal_api_version != HARDWARE_HAL_API_VERSION) ||
        !module->module_api_version || !module->methods || !module->methods->open ||
        !module->name || !module->author) {
        fprintf(stderr, "HMI metadata mismatch\n");
        dlclose(handle);
        return 4;
    }
    printf("HAL_HMI_PASS %s module_api=%u hal_api=%u\n", argv[2],
           (unsigned)module->module_api_version, (unsigned)module->hal_api_version);
    int rc = argc == 4 ? lifecycle(module, argv[2]) : 0;
    int close_rc = dlclose(handle);
    return rc ? rc : close_rc ? 5 : 0;
}
