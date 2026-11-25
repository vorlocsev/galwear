#!/usr/bin/env python3
"""Offline audio routing and ALSA evidence; does not open sound devices."""
from __future__ import annotations
import re
import stat
import xml.etree.ElementTree as ET

from r800_android_userspace_preflight import guest_path, read_regular
from r800_art_launch import executable
from r800_display_inventory import parse_dtb, strings

PARTITIONS = ("vendor", "odm", "system", "product", "system_ext")
MAX_XML = 512 * 1024
MAX_FILES = 128
MAX_SCAN = 4096
MAX_TOTAL = 8 * 1024 * 1024
KERNEL_KEYS = ("CONFIG_SOUND", "CONFIG_SND", "CONFIG_SND_PCM", "CONFIG_SND_SOC",
               "CONFIG_SND_SOC_SAMSUNG", "CONFIG_SND_SOC_SAMSUNG_I2S")
AUDIO_LIB = re.compile(r"(?:audio\.(?:primary|a2dp|usb|r_submix)\.[A-Za-z0-9_.-]+|lib(?:tinyalsa|asound|audiohal|audioclient|audioflinger)|android\.hardware\.audio(?:\.effect)?@[0-9.]+(?:-impl)?)\.so")
CONFIG_NAME = re.compile(r"(?:audio_policy_configuration|audio_policy_volumes|audio_policy_engine_configuration|audio_policy_engine_product_strategies|audio_policy_engine_stream_volumes|audio_policy_engine_volume_groups|mixer_paths|audio_platform_info)(?:_[A-Za-z0-9_.-]+)?\.xml")


def parse_config(raw):
    text = raw.decode("utf-8")
    if "<!" in text or "\0" in text:
        raise ValueError("Unsupported audio XML declaration")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("Malformed audio XML") from exc
    if sum(1 for _ in root.iter()) > 16384:
        raise ValueError("Audio XML record limit exceeded")
    result = {"root": root.tag, "modules": [], "device_ports": [], "mix_ports": [],
              "routes": [], "mixer_paths": [], "includes": [], "review": []}
    for element in root.iter():
        if element.tag.endswith("}include") or element.tag == "include":
            result["includes"].append(element.get("href") or element.get("file") or "")
    if root.tag == "audioPolicyConfiguration":
        for module in root.findall("./modules/module"):
            name = module.get("name", "")
            if not name:
                raise ValueError("Missing audio module name")
            result["modules"].append(name)
            ports = set()
            for kind, tag, attr in (("device_ports", "devicePort", "tagName"),
                                     ("mix_ports", "mixPort", "name")):
                for port in module.findall("./" + ("devicePorts" if kind == "device_ports" else "mixPorts") + "/" + tag):
                    label, role = port.get(attr, ""), port.get("role", "")
                    if not label or label in ports or role not in ("source", "sink"):
                        raise ValueError("Invalid or duplicate audio port")
                    ports.add(label)
                    result[kind].append({"module": name, "name": label, "role": role,
                                         "type": port.get("type")})
            for route in module.findall("./routes/route"):
                sink = route.get("sink", "")
                sources = [s.strip() for s in route.get("sources", "").split(",")]
                if not sink or not all(sources):
                    raise ValueError("Invalid audio route")
                unresolved = sorted(set([sink] + sources) - ports)
                result["routes"].append({"module": name, "sink": sink, "sources": sources,
                                         "unresolved_ports": unresolved})
                if unresolved:
                    result["review"].append("Route endpoints not declared locally: " + sink)
    elif root.tag in ("mixer", "mixer_paths"):
        for path in root.findall("path"):
            name = path.get("name")
            if not name:
                raise ValueError("Unnamed mixer path")
            result["mixer_paths"].append({"name": name, "controls": len(path.findall("ctl")),
                                          "references": [p.get("name") for p in path.findall("path")]})
    else:
        result["review"].append("Uninspected audio XML root")
    return result


def dt_inventory(nodes):
    enabled, result = {}, []
    for path, props in nodes.items():
        parent = path.rsplit("/", 1)[0] or "/"
        status = strings(props.get("status", b""))
        enabled[path] = (not status or status in (["okay"], ["ok"])) and (
            path == "/" or enabled.get(parent, False))
        compatible = strings(props.get("compatible", b""))
        clue = " ".join([path.rsplit("/", 1)[-1]] + compatible).lower()
        if any(term in clue for term in ("sound", "audio", "codec", "i2s", "asoc", "speaker", "microphone")):
            result.append({"path": path, "compatible": compatible, "enabled": enabled[path],
                           "link_properties": sorted(k for k in props if k in
                               ("sound-dai", "audio-routing", "dai-link", "simple-audio-card,name",
                                "simple-audio-card,routing", "model"))})
    return result


def audit(root, init, vintf, inspect_elf, kernel_config=None, dtb=None):
    errors, configs, libraries, services, nodes = [], {}, {}, [], {}
    declared = [e for doc in vintf["files"].values()
                if doc["kind"] == "manifest" and doc["type"] == "device"
                for e in doc["entries"] if e["name"] in
                ("android.hardware.audio", "android.hardware.audio.effect", "android.hardware.soundtrigger")]
    for s in init.get("audio_services", []):
        item = {"name": s["name"], "path": s["executable"], "elf": None}
        services.append(item)
        try:
            item["elf"] = executable(root, item["path"])
        except (OSError, ValueError) as exc:
            errors.append(item["name"] + ": " + str(exc))
    if len([s for s in services if s["name"] == "audioserver" and s["elf"]]) != 1:
        errors.append("Missing or ambiguous inspected audioserver")
    scanned = total = elf_total = 0
    for partition in PARTITIONS:
        for directory, pattern, abi in (("/etc", CONFIG_NAME, None),
                                         ("/lib/hw", AUDIO_LIB, "arm"),
                                         ("/lib64/hw", AUDIO_LIB, "arm64"),
                                         ("/lib", AUDIO_LIB, "arm"),
                                         ("/lib64", AUDIO_LIB, "arm64")):
            base = "/" + partition + directory
            try:
                names = []
                for entry in guest_path(root, base).iterdir():
                    scanned += 1
                    if scanned > MAX_SCAN:
                        raise ValueError("Audio directory scan limit exceeded")
                    if pattern.fullmatch(entry.name):
                        names.append(entry.name)
                        if len(names) > MAX_FILES:
                            raise ValueError("Audio candidate limit exceeded")
                for name in sorted(names):
                    if len(configs) + len(libraries) >= MAX_FILES:
                        raise ValueError("Audio file limit exceeded")
                    guest = base + "/" + name
                    target = libraries if abi else configs
                    target[guest] = None
                    try:
                        path = guest_path(root, guest)
                        size = path.lstat().st_size
                        if abi:
                            if elf_total + size > 256 * 1024 * 1024:
                                raise ValueError("Audio ELF aggregate budget exceeded")
                            raw = read_regular(path, 64 * 1024 * 1024)
                            elf_total += len(raw)
                            info = inspect_elf(raw)
                            if info["abi"] != abi or info["elf_type"] != "ET_DYN" or not info["has_dynamic"]:
                                raise ValueError("Audio library ELF ABI or type mismatch")
                            target[guest] = {"abi": abi, "needed": info["needed"], "soname": info["soname"]}
                        else:
                            if total + size > MAX_TOTAL:
                                raise ValueError("Audio XML aggregate budget exceeded")
                            raw = read_regular(path, MAX_XML)
                            total += len(raw)
                            target[guest] = parse_config(raw)
                    except (OSError, ValueError) as exc:
                        errors.append(guest + ": " + str(exc))
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                errors.append(base + ": " + str(exc))
    snapshots = {}
    for guest in ("/proc/asound/cards", "/proc/asound/pcm", "/proc/asound/devices"):
        try:
            snapshots[guest] = read_regular(guest_path(root, guest), 65536).decode("utf-8")
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(guest + ": " + str(exc))
    try:
        for index, entry in enumerate(guest_path(root, "/dev/snd").iterdir()):
            if index >= MAX_SCAN:
                raise ValueError("Sound device scan limit exceeded")
            if re.fullmatch(r"(?:controlC[0-9]+|pcmC[0-9]+D[0-9]+[pc])", entry.name):
                guest = "/dev/snd/" + entry.name
                nodes[guest] = stat.S_ISCHR(guest_path(root, guest).lstat().st_mode)
                if not nodes[guest]:
                    errors.append(guest + ": not a character device")
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    dt = []
    if dtb is not None:
        try:
            dt = dt_inventory(parse_dtb(dtb))
        except ValueError as exc:
            errors.append(str(exc))
    ports = [p for config in configs.values() if config for p in config["device_ports"]]
    speaker = any(p["type"] == "AUDIO_DEVICE_OUT_SPEAKER" and p["role"] == "sink" for p in ports)
    mic = any(p["type"] in ("AUDIO_DEVICE_IN_BUILTIN_MIC", "AUDIO_DEVICE_IN_BACK_MIC") and p["role"] == "source" for p in ports)
    review = [path for path, config in configs.items() if config and (config["review"] or config["includes"])]
    primary = [p for p, info in libraries.items() if info and p.rsplit("/", 1)[1].startswith("audio.primary.")]
    return {"status": "STATIC_AUDIO_INVENTORY_ONLY" if not errors and not review and
            speaker and mic and primary and any(e["name"] == "android.hardware.audio" for e in declared)
            else "REVIEW_REQUIRED",
            "hal_declarations": declared, "services": services, "configs": configs,
            "libraries": libraries, "primary_candidates": primary, "configuration_review": review,
            "speaker_port_declared": speaker, "microphone_port_declared": mic,
            "dt_candidates": dt, "alsa_snapshots": snapshots, "device_nodes": nodes,
            "kernel_config": None if kernel_config is None else {k: kernel_config.get(k) for k in KERNEL_KEYS},
            "errors": errors, "alsa_runtime_verified": False, "audio_hal_registered": False,
            "speaker_playback_verified": False, "microphone_capture_verified": False,
            "codec_driver_verified": False, "safe_to_flash": False}
