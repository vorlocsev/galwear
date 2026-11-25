#!/usr/bin/env python3
"""Static Binder and SystemServer prerequisites; no guest IPC or execution."""
from __future__ import annotations

import stat
from r800_android_userspace_preflight import guest_path, read_regular
from r800_art_launch import executable

DEVICES = ("binder", "hwbinder", "vndbinder")
SERVICES = {"servicemanager": "/system/bin/servicemanager",
            "hwservicemanager": "/system/bin/hwservicemanager",
            "vndservicemanager": "/vendor/bin/vndservicemanager"}
MAX_RC = 256 * 1024
RC_FILES = ("/ueventd.rc", "/system/etc/ueventd.rc", "/vendor/ueventd.rc",
            "/vendor/etc/ueventd.rc", "/odm/ueventd.rc")


def kernel_evidence(values):
    if values is None:
        return {"status": "NOT_PROVIDED", "missing": [], "runtime_verified": False}
    devices = values.get("CONFIG_ANDROID_BINDER_DEVICES", "").strip('"').split(",")
    missing = []
    for key in ("CONFIG_ANDROID_BINDER_IPC", "CONFIG_COMPAT"):
        if values.get(key) != "y":
            missing.append(key)
    if not set(DEVICES) <= set(devices):
        missing.append("CONFIG_ANDROID_BINDER_DEVICES")
    return {"status": "CONFIG_EVIDENCE_ONLY" if not missing else "REVIEW_REQUIRED",
            "missing": missing, "binderfs_config": values.get("CONFIG_ANDROID_BINDERFS"),
            "configured_devices": devices, "runtime_verified": False}


def audit(root, init, art, launch, kernel_config=None):
    errors, managers, nodes, rules = [], {}, {}, []
    for name, default in SERVICES.items():
        declarations = [s for s in init["services"] if s["name"] == name]
        item = {"declarations": declarations, "default_path": default, "elf": None}
        managers[name] = item
        if len(declarations) != 1:
            errors.append("Missing or ambiguous service: " + name)
            continue
        try:
            item["elf"] = executable(root, declarations[0]["executable"])
        except (OSError, ValueError) as exc:
            errors.append(name + ": " + str(exc))
    for name in DEVICES:
        path = "/dev/" + name
        nodes[name] = {"path": path, "character_device_present": False}
        try:
            mode = guest_path(root, path).lstat().st_mode
            nodes[name]["character_device_present"] = stat.S_ISCHR(mode)
            if not stat.S_ISCHR(mode):
                errors.append(path + ": not a character device")
        except FileNotFoundError:
            # Device nodes normally appear only during boot.
            pass
        except (OSError, ValueError) as exc:
            errors.append(path + ": " + str(exc))
    unresolved_imports = []
    for path in RC_FILES:
        try:
            text = read_regular(guest_path(root, path), MAX_RC).decode("utf-8")
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(path + ": " + str(exc))
            continue
        for line in text.splitlines():
            parts = line.split("#", 1)[0].split()
            if len(parts) == 2 and parts[0] == "import":
                unresolved_imports.append({"source": path, "path": parts[1]})
            if parts and parts[0] in {"/dev/" + name for name in DEVICES}:
                if len(parts) != 4 or len(parts[1]) not in (3, 4) or any(
                        ch not in "01234567" for ch in parts[1]):
                    errors.append(path + ": malformed Binder permission rule")
                    continue
                rules.append({"source": path, "device": parts[0], "mode": parts[1],
                              "owner": parts[2], "group": parts[3]})
                if len(rules) > 256:
                    errors.append("Binder rule inventory limit exceeded")
                    break
    cp = art["classpath_exports"].get("SYSTEMSERVERCLASSPATH", [])
    classpaths = cp[0].split(":") if len(cp) == 1 else []
    missing = [p for p in classpaths if not art["artifacts"].get(p) or
               art["artifacts"][p]["status"] != "DEX_HEADER_INVENTORY_ONLY"]
    server = {"classpath": classpaths, "missing_or_unverified": missing,
              "zygote_argument_present": bool(launch["zygote_services"].get("zygote", {}).get(
                  "system_server_arg")), "started": False}
    if not classpaths or missing or not server["zygote_argument_present"]:
        errors.append("SystemServer launch evidence incomplete")
    kernel = kernel_evidence(kernel_config)
    return {"status": "STATIC_BINDER_INVENTORY_ONLY" if not errors and not unresolved_imports and
            kernel["status"] == "CONFIG_EVIDENCE_ONLY" else "REVIEW_REQUIRED",
            "managers": managers, "device_nodes": nodes, "ueventd_rules": rules,
            "unresolved_ueventd_imports": unresolved_imports,
            "init_commands": init.get("binder_commands", []), "kernel": kernel,
            "system_server": server, "errors": errors,
            "binder_transaction_verified": False, "service_registration_verified": False,
            "system_server_started": False, "safe_to_flash": False}
