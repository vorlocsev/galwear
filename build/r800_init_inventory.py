#!/usr/bin/env python3
"""Bounded static Android init.rc inventory. Does not execute init commands."""
from __future__ import annotations

import re
import shlex
from r800_android_userspace_preflight import guest_path, read_regular

MAX_RC = 256 * 1024
MAX_FILES = 256
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 32768
SERVICE_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
ROOT_FILES = ("/init.rc", "/system/etc/init/hw/init.rc")
ROOT_DIRS = ("/system/etc/init", "/system_ext/etc/init", "/vendor/etc/init",
             "/odm/etc/init", "/product/etc/init")
APEX_SERVICES = ("apexd", "apexd-bootstrap", "apexd-snapshotde")


def tokens(text):
    pending = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        if not pending:
            start = number
        line = raw.rstrip()
        if line.endswith("\\"):
            pending += line[:-1] + " "
            if len(pending) > 16384:
                raise ValueError("Init continuation exceeds limit")
            continue
        line = pending + line
        pending = ""
        if len(line) > 16384:
            raise ValueError("Init line exceeds limit")
        try:
            parts = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise ValueError("Invalid init quoting at line " + str(start)) from exc
        if parts:
            yield start, parts
    if pending:
        raise ValueError("Unterminated init continuation")


def parse(text, source):
    services, actions, imports, unknown = [], [], [], []
    current = None
    for number, parts in tokens(text):
        key, args = parts[0], parts[1:]
        if key == "service":
            if len(args) < 2 or not SERVICE_NAME.fullmatch(args[0]) or not args[1].startswith("/"):
                raise ValueError("Invalid init service at line " + str(number))
            current = {"name": args[0], "executable": args[1], "args": args[2:],
                       "source": source, "line": number, "options": []}
            services.append(current)
        elif key == "on":
            if not args:
                raise ValueError("Empty init trigger")
            current = {"trigger": " ".join(args), "source": source, "line": number,
                       "commands": []}
            actions.append(current)
        elif key == "import":
            if len(args) != 1:
                raise ValueError("Invalid init import")
            imports.append(args[0])
            current = None
        elif current is not None:
            current["options" if "options" in current else "commands"].append(
                {"name": key, "args": args, "line": number})
        else:
            unknown.append({"source": source, "line": number, "name": key})
    return services, actions, imports, unknown


def audit(root):
    errors, unresolved, unknown, files = [], [], [], []
    services, actions = [], []
    pending = list(ROOT_FILES)
    queued = set(pending)
    seen = set()
    total = records = 0

    def enqueue(path):
        if path not in queued:
            if len(queued) >= MAX_FILES * 2:
                raise ValueError("Init import queue limit exceeded")
            pending.append(path)
            queued.add(path)

    def enqueue_directory(path):
        directory = guest_path(root, path)
        if not directory.is_dir():
            raise ValueError("Init directory is not a directory")
        children = []
        for entry in directory.iterdir():
            if entry.name.endswith(".rc"):
                children.append(entry.name)
                if len(children) > MAX_FILES:
                    raise ValueError("Init directory entry limit exceeded")
        for name in sorted(children):
            enqueue(path.rstrip("/") + "/" + name)

    for directory in ROOT_DIRS:
        try:
            enqueue_directory(directory)
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(directory + ": " + str(exc))

    while pending:
        path = pending.pop(0)
        try:
            resolved = guest_path(root, path)
            if resolved.is_dir():
                enqueue_directory(path)
                continue
            if resolved in seen:
                continue
            if len(seen) >= MAX_FILES:
                raise ValueError("Init file limit exceeded")
            seen.add(resolved)
            raw = read_regular(resolved, MAX_RC)
            total += len(raw)
            if total > MAX_TOTAL_BYTES:
                raise ValueError("Init aggregate byte limit exceeded")
            s, a, imports, other = parse(raw.decode("utf-8"), path)
            records += len(s) + len(a) + sum(len(x["options"]) for x in s) + sum(
                len(x["commands"]) for x in a) + len(imports) + len(other)
            if records > MAX_RECORDS:
                raise ValueError("Init record limit exceeded")
            files.append(path)
            services.extend(s)
            actions.extend(a)
            unknown.extend(other)
            for item in imports:
                if not item.startswith("/") or ".." in item.split("/") or any(
                        ch in item for ch in "$*?{}[]"):
                    unresolved.append({"source": path, "import": item})
                else:
                    enqueue(item)
        except FileNotFoundError:
            if path not in ROOT_FILES:
                unresolved.append({"source": path, "import": path})
        except (OSError, ValueError) as exc:
            errors.append(path + ": " + str(exc))
            if total > MAX_TOTAL_BYTES or records > MAX_RECORDS:
                break

    binder_services = ("servicemanager", "hwservicemanager", "vndservicemanager")
    graphics_services = [s for s in services if s["name"] == "surfaceflinger" or
        any("graphics." in arg for o in s["options"] if o["name"] == "interface" for arg in o["args"]) or
        any(part in s["name"].lower() for part in ("composer", "gralloc", "allocator", "mapper", "mali"))]
    audio_services = [s for s in services if s["name"] == "audioserver" or
        any("android.hardware.audio" in arg for o in s["options"] if o["name"] == "interface" for arg in o["args"]) or
        any(part in s["name"].lower() for part in ("audio", "soundtrigger"))]
    bluetooth_services = [s for s in services if
        any("android.hardware.bluetooth" in arg for o in s["options"] if o["name"] == "interface" for arg in o["args"]) or
        any(part in s["name"].lower() for part in ("bluetooth", "btattach", "hciattach"))]
    wifi_services = [s for s in services if
        any("android.hardware.wifi" in arg for o in s["options"] if o["name"] == "interface" for arg in o["args"]) or
        any(part in s["name"].lower() for part in ("wifi", "wlan", "supplicant", "hostapd", "wificond"))]
    gnss_services = [s for s in services if
        any("android.hardware.gnss" in arg for o in s["options"] if o["name"] == "interface" for arg in o["args"]) or
        any(part in s["name"].lower() for part in ("gnss", "gps", "glgps", "loc_launcher"))]
    relevant = [s for s in services if s in graphics_services or s in audio_services or s in bluetooth_services or s in wifi_services or s in gnss_services or s["name"] in APEX_SERVICES + binder_services or
                s["name"].startswith("zygote") or "art" in s["name"].split("-")]
    duplicates = []
    by_name = {}
    for service in services:
        previous = by_name.get(service["name"])
        if previous is not None:
            duplicates.append({"name": service["name"], "sources": [previous["source"], service["source"]],
                               "override_declared": any(o["name"] == "override" for o in service["options"])})
        by_name[service["name"]] = service
    evidence = []
    binder_commands = []
    environment = []
    for action in actions:
        for command in action["commands"]:
            key, args = command["name"], command["args"]
            if (key in ("start", "exec_start", "restart", "stop") and args and
                    args[0] in APEX_SERVICES or
                    key in ("perform_apex_config", "update_linker_config") or
                    key == "setprop" and args and args[0].startswith("apexd.") or
                    "apexd.status" in action["trigger"]):
                evidence.append({"trigger": action["trigger"], "source": action["source"], **command})
            if ((key in ("start", "exec_start", "restart", "stop") and args and args[0] in binder_services) or
                    (key in ("chmod", "chown", "wait", "symlink") and any(
                        arg in ("/dev/binder", "/dev/hwbinder", "/dev/vndbinder") for arg in args)) or
                    (key == "mount" and args and args[0] == "binder")):
                binder_commands.append({"trigger": action["trigger"], "source": action["source"], **command})
            if key == "export" and args and args[0] in (
                    "ANDROID_ROOT", "ANDROID_ART_ROOT", "ANDROID_RUNTIME_ROOT",
                    "BOOTCLASSPATH", "DEX2OATBOOTCLASSPATH", "SYSTEMSERVERCLASSPATH"):
                environment.append({"trigger": action["trigger"], "source": action["source"], **command})
    missing = []
    if not files:
        missing.append("No init configuration files inspected")
    if not any(s["name"] == "apexd" for s in relevant):
        missing.append("apexd service declaration unavailable")
    if not evidence:
        missing.append("APEX activation command or trigger unavailable")
    return {"status": "STATIC_INIT_INVENTORY_ONLY" if not (errors or unresolved or unknown or
                 duplicates or missing) else "REVIEW_REQUIRED",
            "files": files, "services": relevant, "activation_commands": evidence,
            "binder_commands": binder_commands,
            "graphics_services": graphics_services,
            "audio_services": audio_services,
            "bluetooth_services": bluetooth_services,
            "wifi_services": wifi_services,
            "gnss_services": gnss_services,
            "art_environment": environment, "duplicate_services": duplicates,
            "unresolved_imports": unresolved, "unknown_top_level": unknown,
            "missing_evidence": missing, "errors": errors,
            "init_execution_verified": False, "apexd_activation_verified": False,
            "art_initialization_verified": False, "safe_to_flash": False}
