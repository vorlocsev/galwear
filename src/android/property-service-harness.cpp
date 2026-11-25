// SPDX-License-Identifier: Apache-2.0
// Experimental AOSP libinit entry point, not Android first/second stage init.
// Run ONLY in a disposable virt guest with prepared Android property contexts.
#include <android-base/logging.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include "property_service.h"

int main(int argc, char** argv) {
    if (argc != 2 || strcmp(argv[1], "--virt-property-service") || getpid() != 1)
        return 2;
    // Never initialize properties on an existing Android installation.
    struct stat st {};
    if (lstat("/dev/__properties__", &st) == 0 || errno != ENOENT ||
        lstat("/dev/socket/property_service", &st) == 0 || errno != ENOENT ||
        lstat("/dev/socket", &st) != 0 || !S_ISDIR(st.st_mode))
        return 3;
    std::puts("r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover");
    std::fflush(stdout);
    android::base::InitLogging(argv, &android::base::StderrLogger);
    android::init::PropertyInit();
    int init_socket = -1;
    android::init::StartPropertyService(&init_socket);
    if (init_socket < 0 || lstat("/dev/socket/property_service", &st) ||
        !S_ISSOCK(st.st_mode))
        return 4;
    // This is only service startup evidence, not client transaction evidence.
    std::puts("r800-property-service: original-libinit socket-created");
    std::fflush(stdout);
    pid_t child = fork();
    if (child < 0) return 5;
    if (child == 0) {
        char path[] = "/system/bin/galwear_property_client";
        char mode[] = "--virt-property-client";
        char* const args[] = {path, mode, nullptr};
        char* const env[] = {nullptr};
        execve(path, args, env);
        _exit(127);
    }
    int status = 0;
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status))
        return 6;
    std::puts("r800-property-service: client-exit=0");
    std::fflush(stdout);
    // Keep libinit's service thread and internal socket alive. This harness
    // does not implement the full init event loop, ctl.* or persistent props.
    unsigned int heartbeat = 0;
    for (;;) {
        if (sleep(5) == 0 && heartbeat != 0xffffffffU) {
            std::printf("r800-readonly-init: heartbeat %08x\n", ++heartbeat);
            std::fflush(stdout);
        }
    }
}
