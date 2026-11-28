// SPDX-License-Identifier: Apache-2.0
// Development-only Android 11 AIDL adapter; no hardware acceptance claim.
#include <aidl/android/hardware/light/BnLights.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <hardware/hardware.h>
#include <hardware/lights.h>
#include <dlfcn.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace {
using aidl::android::hardware::light::BnLights;
using aidl::android::hardware::light::HwLight;
using aidl::android::hardware::light::HwLightState;
using aidl::android::hardware::light::LightType;

constexpr char kModule[] = "/vendor/lib/hw/lights.r800.so";
constexpr int32_t kBacklightId = 1;

// No implicit hardware module search or fallback to another donor's HAL.
class Backend {
public:
    Backend() = default;
    Backend(const Backend&) = delete;
    Backend& operator=(const Backend&) = delete;
    ~Backend() {
        if (device_) device_->common.close(&device_->common);
        if (library_) dlclose(library_);
    }

    bool initialize() {
        library_ = dlopen(kModule, RTLD_NOW | RTLD_LOCAL);
        if (!library_) return false;
        const auto* module = static_cast<const hw_module_t*>(
            dlsym(library_, HAL_MODULE_INFO_SYM_AS_STR));
        if (!module || module->tag != HARDWARE_MODULE_TAG || !module->id ||
            std::strcmp(module->id, LIGHTS_HARDWARE_MODULE_ID) ||
            !module->methods || !module->methods->open) return false;

        hw_device_t* raw = nullptr;
        const int rc = module->methods->open(module, LIGHT_ID_BACKLIGHT, &raw);
        if (rc != 0 || !raw) return false;
        if (raw->tag != HARDWARE_DEVICE_TAG || !raw->close || raw->module != module) {
            if (raw->tag == HARDWARE_DEVICE_TAG && raw->close) raw->close(raw);
            return false;
        }
        device_ = reinterpret_cast<light_device_t*>(raw);
        if (!device_->set_light) {
            raw->close(raw);
            device_ = nullptr;
            return false;
        }
        return true;
    }

    int apply(int32_t color) {
        std::lock_guard<std::mutex> guard(lock_);
        if (!device_) return -ENODEV;
        light_state_t state{};
        // Only steady backlight is supported. Preserve RGB; the existing
        // legacy module computes luminance and handles writes and retries.
        state.color = static_cast<unsigned int>(color);
        state.flashMode = LIGHT_FLASH_NONE;
        state.brightnessMode = BRIGHTNESS_MODE_USER;
        return device_->set_light(device_, &state);
    }

private:
    void* library_ = nullptr;
    light_device_t* device_ = nullptr;
    std::mutex lock_;
};

class Lights final : public BnLights {
public:
    bool initialize() { return backend_.initialize(); }

    ndk::ScopedAStatus getLights(std::vector<HwLight>* lights) override {
        HwLight light{};
        light.id = kBacklightId;
        light.ordinal = 0;
        light.type = LightType::BACKLIGHT;
        *lights = {light};
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus setLightState(int32_t id, const HwLightState& state) override {
        if (id != kBacklightId) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
        }
        const int rc = backend_.apply(state.color);
        if (rc != 0) {
            // Unsupported flash/brightness modes are best-effort per ILights.
            // Actual sysfs failures are not silently reported as success.
            return ndk::ScopedAStatus::fromServiceSpecificError(rc < 0 ? -rc : EIO);
        }
        return ndk::ScopedAStatus::ok();
    }

private:
    Backend backend_;
};
}  // namespace

int main() {
    auto service = ndk::SharedRefBase::make<Lights>();
    if (!service->initialize()) {
        std::fprintf(stderr, "GalWear Lights: R800 backend initialization failed\n");
        return 1;
    }
    ABinderProcess_setThreadPoolMaxThreadCount(0);
    const std::string instance = std::string(Lights::descriptor) + "/default";
    if (AServiceManager_addService(service->asBinder().get(), instance.c_str()) != STATUS_OK) {
        std::fprintf(stderr, "GalWear Lights: binder registration failed\n");
        return 2;
    }
    ABinderProcess_joinThreadPool();
    return 3;
}
