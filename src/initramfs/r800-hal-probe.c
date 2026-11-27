/* ARM32 Bionic diagnostic only. Never call HAL hardware entrypoints. */
#include <dlfcn.h>
#include <hardware/hardware.h>
#include <stdio.h>
#include <string.h>

#if !defined(__BIONIC__) || !defined(__arm__) || __ANDROID_API__ != 28
#error "ARM32 Bionic API28 required"
#endif
_Static_assert(sizeof(hw_module_t) == 128, "Unexpected HAL module ABI");

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
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
    return dlclose(handle) ? 5 : 0;
}
