#!/usr/bin/env python3
"""Offline graphics candidate inventory; does not initialize EGL or access devices."""
from __future__ import annotations
import hashlib
import re
import stat

from r800_android_userspace_preflight import guest_path, read_regular
from r800_art_launch import executable
from r800_display_inventory import parse_dtb, strings

MAX_ELF = 64 * 1024 * 1024
MAX_SCAN = 8192
MAX_LIBRARIES = 128
MAX_LIBRARY_BYTES = 256 * 1024 * 1024
HALS = ("composer", "allocator", "mapper")
PARTITIONS = ("system", "vendor", "odm", "system_ext", "product")
LIB_PATTERN = re.compile(r"(?:lib(?:EGL|GLESv1_CM|GLESv2|GLES|Mali|mali|gralloc|hwcomposer)(?:[._-][A-Za-z0-9_.-]+)?|(?:gralloc|hwcomposer)\.[A-Za-z0-9_.-]+|android\.hardware\.graphics\.(?:composer|allocator|mapper)@[0-9.]+(?:-impl(?:-[A-Za-z0-9_.-]+)?)?)\.so")
DEVICES = ("/dev/mali0", "/dev/mali", "/dev/graphics/fb0", "/dev/dri/card0",
           "/dev/dri/renderD128")
KERNEL_KEYS = ("CONFIG_DRM", "CONFIG_FB", "CONFIG_DRM_EXYNOS", "CONFIG_MALI_MIDGARD",
               "CONFIG_MALI_BIFROST", "CONFIG_MALI_KBASE", "CONFIG_SYNC_FILE",
               "CONFIG_DMA_SHARED_BUFFER", "CONFIG_ION", "CONFIG_DMABUF_HEAPS")


EGL_PROPERTY_FILES = ("/system/build.prop", "/system/etc/build.prop",
                      "/vendor/build.prop", "/vendor/etc/build.prop",
                      "/odm/build.prop", "/odm/etc/build.prop",
                      "/product/build.prop", "/product/etc/build.prop",
                      "/system_ext/build.prop", "/system_ext/etc/build.prop",
                      "/default.prop", "/prop.default")
EGL_HINT_KEYS = ("persist.graphics.egl", "ro.hardware.egl", "ro.board.platform")
EGL_SUFFIX = re.compile(r"[A-Za-z0-9_-]{1,80}")
EGL_DRIVER = re.compile(r"(libEGL|libGLESv1_CM|libGLESv2|libGLES)(?:_([A-Za-z0-9_-]+))?\.so")


# Minimum diagnostic subset, not a complete Khronos conformance contract.
ENTRYPOINTS = {
    "libEGL": ("eglGetDisplay", "eglInitialize", "eglChooseConfig",
               "eglCreateContext", "eglDestroyContext", "eglMakeCurrent",
               "eglGetProcAddress", "eglSwapBuffers", "eglTerminate"),
    "libGLESv2": ("glGetString", "glGetError", "glClear", "glDrawArrays",
                  "glCreateShader", "glShaderSource", "glCompileShader",
                  "glCreateProgram", "glLinkProgram", "glUseProgram"),
    "libGLESv1_CM": ("glGetString", "glGetError", "glClear", "glDrawArrays"),
}


def entrypoint_evidence(path, info):
    """Report directly visible defined exports only; never infer dlsym success."""
    name = path.rsplit("/", 1)[1]
    match = EGL_DRIVER.fullmatch(name)
    role = match.group(1) if match else None
    if role == "libGLES":
        required = sorted(set(ENTRYPOINTS["libEGL"] + ENTRYPOINTS["libGLESv2"]))
    elif role in ENTRYPOINTS:
        required = list(ENTRYPOINTS[role])
    elif re.fullmatch(r"android\.hardware\.graphics\.mapper@2\.[01]-impl(?:-[A-Za-z0-9_.-]+)?\.so", name):
        role, required = "mapper_factory", ["HIDL_FETCH_IMapper"]
    elif name.startswith(("gralloc.", "hwcomposer.")) and path.rsplit("/",1)[0].endswith("/hw"):
        role, required = "legacy_hal", ["HMI"]
    else:
        return {"status": "NO_ENTRYPOINT_POLICY", "role": None,
                "runtime_resolution_verified": False}
    # STT_FUNC / STT_NOTYPE for functions (NOTYPE is a review candidate, not
    # proof of a callable function); HMI must be a data object.
    allowed = {1} if role == "legacy_hal" else {2}
    found, untyped, incompatible = set(), set(), set()
    checked = info.get("dynamic_symbol_count") is not None
    for symbol in info.get("symbol_exports", ()):
        symbol_name = symbol["name"]
        if symbol_name not in required:
            continue
        if (symbol.get("version_hidden") or symbol.get("binding") not in (1, 2)
                or symbol.get("visibility") not in (0, 3)):
            incompatible.add(symbol_name)
        elif symbol["type"] in allowed:
            found.add(symbol_name)
        elif role != "legacy_hal" and symbol["type"] == 0:
            untyped.add(symbol_name)
        else:
            incompatible.add(symbol_name)
    missing = sorted(set(required) - found)
    return {"status": ("UNINSPECTED" if not checked else
                       "STATIC_MINIMUM_EXPORTS_ONLY" if not missing else "REVIEW_REQUIRED"),
            "role": role, "required": required, "direct_exports": sorted(found),
            "missing_or_unconfirmed": missing,
            "untyped_candidates": sorted(untyped - found),
            "incompatible_candidates": sorted(incompatible - found),
            "runtime_resolution_verified": False}


def graphics_entrypoints(libraries, groups, abi):
    selected = {path: info["entrypoints"] for path, info in libraries.items()
                if info and info["abi"] == abi and
                info["entrypoints"]["status"] != "NO_ENTRYPOINT_POLICY"}
    complete = []
    for group in groups["groups"]:
        if not group["structurally_complete"]:
            continue
        roles = group["libraries"]
        def good(role):
            return selected.get(roles.get(role), {}).get("status") == "STATIC_MINIMUM_EXPORTS_ONLY"
        # Alternative combined/split layouts are reported independently.
        combined = good("libGLES")
        split = good("libEGL") and good("libGLESv2")
        complete.append({"directory": group["directory"], "suffix": group["suffix"],
                         "combined_minimum_exports": combined, "split_minimum_exports": split})
    blockers = sorted(path for path, item in selected.items()
                      if item["status"] != "STATIC_MINIMUM_EXPORTS_ONLY")
    ready = (groups["status"] == "STATIC_EGL_DRIVER_GROUP_ONLY" and
             len(complete) == 1 and
             (complete[0]["combined_minimum_exports"] or complete[0]["split_minimum_exports"])
             and not blockers)
    return {"status": "STATIC_GRAPHICS_MINIMUM_EXPORTS_ONLY" if ready else "REVIEW_REQUIRED",
            "abi": abi, "libraries": selected, "groups": complete,
            "review_libraries": blockers, "runtime_resolution_verified": False,
            "egl_initialized": False, "safe_to_flash": False}


def mapper_factory_evidence(libraries, abi):
    """Inspect factory exports without calling HIDL or inferring interfaceChain."""
    candidates, other_abi, invalid = {}, [], []
    for path, info in sorted(libraries.items()):
        name = path.rsplit("/", 1)[-1]
        if not re.fullmatch(r"android\.hardware\.graphics\.mapper@2\.[01]-impl(?:-[A-Za-z0-9_.-]+)?\.so", name):
            continue
        if not info or info.get("abi") not in ("arm", "arm64"):
            invalid.append(path)
        elif abi not in ("arm", "arm64") or info["abi"] != abi:
            other_abi.append(path)
        else:
            candidates[path] = info.get("entrypoints", {})
    direct = sorted(path for path, evidence in candidates.items()
                    if evidence.get("role") == "mapper_factory"
                    and evidence.get("status") == "STATIC_MINIMUM_EXPORTS_ONLY"
                    and "HIDL_FETCH_IMapper" in evidence.get("direct_exports", []))
    blockers = []
    if abi not in ("arm", "arm64"):
        blockers.append("Client ABI unavailable")
    if len(candidates) != 1 or len(direct) != 1:
        blockers.append("Missing or ambiguous same-ABI direct mapper factory export")
    if invalid:
        blockers.append("Invalid mapper implementation ELF candidates")
    return {"status": "STATIC_MAPPER_FACTORY_EXPORT_ONLY" if not blockers else "REVIEW_REQUIRED",
            "client_abi": abi, "candidates": candidates, "direct_factory_candidates": direct,
            "other_abi_candidates": other_abi, "invalid_candidates": invalid, "blockers": blockers,
            "factory_called": False, "interface_chain_verified": False,
            "mapper_2_1_verified": False, "buffer_import_verified": False,
            "hardware_tested": False, "safe_to_flash": False}


def mapper_2_1_evidence(declared, libraries, abi):
    """Literal mapper candidates for the SurfaceFlinger ABI, not HIDL execution."""
    package = "android.hardware.graphics.mapper"
    entries = [item for item in declared
               if item.get("name") == package and item.get("format") == "hidl"
               and item.get("interface") == "IMapper" and item.get("instance") == "default"]
    exact = [item for item in entries if item.get("version") == [2, 1, 1]]
    passthrough = [item for item in exact if item.get("transport") == "passthrough"]
    interface_name = package + "@2.1.so"
    implementation_name = package + "@2.1-impl.so"
    interfaces, implementations, other_abi, invalid, legacy = [], [], [], [], []
    for path, info in sorted(libraries.items()):
        directory, name = path.rsplit("/", 1)
        if name.startswith("gralloc.") and directory.endswith("/hw"):
            if info and abi in ("arm", "arm64") and info.get("abi") == abi:
                legacy.append(path)
            continue
        if name not in (interface_name, implementation_name):
            continue
        if not info or info.get("abi") not in ("arm", "arm64"):
            invalid.append(path)
        elif abi not in ("arm", "arm64") or info["abi"] != abi:
            other_abi.append(path)
        elif name == interface_name:
            interfaces.append(path)
        else:
            implementations.append(path)
    blockers = []
    if abi not in ("arm", "arm64"):
        blockers.append("SurfaceFlinger ABI unavailable")
    if len(passthrough) != 1 or len(exact) != 1 or len(entries) != 1:
        blockers.append("Missing or ambiguous literal IMapper 2.1 default passthrough declaration")
    if len(interfaces) != 1:
        blockers.append("Missing or ambiguous same-ABI mapper 2.1 interface library")
    if len(implementations) != 1:
        blockers.append("Missing or ambiguous same-ABI mapper 2.1 implementation library")
    if invalid:
        blockers.append("Uninspected or invalid mapper 2.1 ELF candidates")
    # Do not infer inherited versions, VINTF merge, transport arch, namespace
    # resolution, HIDL factory symbols, or private native_handle compatibility.
    return {"status": "STATIC_MAPPER_2_1_CANDIDATES_ONLY" if not blockers else "REVIEW_REQUIRED",
            "surfaceflinger_abi": abi, "literal_declarations": entries,
            "exact_passthrough_declarations": passthrough,
            "interface_candidates": interfaces, "implementation_candidates": implementations,
            "other_abi_candidates": other_abi, "invalid_candidates": invalid,
            "legacy_gralloc_candidates": legacy, "blockers": blockers,
            "vintf_merge_verified": False, "transport_arch_verified": False,
            "namespace_resolution_verified": False, "mapper_factory_verified": False,
            "mapper_2_1_verified": False, "native_handle_abi_verified": False,
            "buffer_import_verified": False, "hardware_tested": False, "safe_to_flash": False}


def hwc_stride_evidence(root):
    """Inventory static property assignments, never infer the donor caller ABI."""
    key = "debug.r800.layer_stride"
    hints, errors = [], []
    for source in EGL_PROPERTY_FILES:
        try:
            raw = read_regular(guest_path(root, source), 1024 * 1024).decode("utf-8")
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(source + ": " + str(exc))
            continue
        for number, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = (v.strip() for v in line.split("=", 1))
            if name != key:
                continue
            hints.append({"source": source, "line": number, "value": value})
            if value not in ("96", "100"):
                errors.append(source + ":" + str(number) + ": invalid HWC stride hint")
    values = sorted({hint["value"] for hint in hints})
    conflict = len(values) > 1
    observed = int(values[0]) if not errors and len(values) == 1 and values[0] in ("96", "100") else None
    # A property only chooses a stride. It cannot establish the caller's
    # actual allocation size, field offsets or ABI at runtime.
    return {"status": "REVIEW_REQUIRED", "property": key, "assignments": hints,
            "conflicting_assignments": conflict, "errors": errors,
            "observed_explicit_stride": observed,
            "historical_default_stride": 100, "aosp_arm32_layer_bytes": 96,
            "runtime_effective_stride": None, "donor_layer_layout_verified": False,
            "donor_layer_stride_100_verified": False, "mapper_2_1_verified": False,
            "hardware_tested": False, "safe_to_flash": False}


def egl_driver_candidates(root, libraries, abi):
    """Group drivers by ABI, directory and suffix; do not predict runtime priority."""
    hints, errors, groups = {}, [], {}
    for source in EGL_PROPERTY_FILES:
        try:
            raw = read_regular(guest_path(root, source), 1024*1024).decode("utf-8")
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(source + ": " + str(exc))
            continue
        for number, line in enumerate(raw.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = (v.strip() for v in line.split("=", 1))
            if key not in EGL_HINT_KEYS:
                continue
            if not EGL_SUFFIX.fullmatch(value):
                errors.append(source + ":" + str(number) + ": invalid EGL hint " + key)
                continue
            hints.setdefault(key, []).append({"value": value, "source": source, "line": number})
    conflicts = sorted(key for key, records in hints.items()
                       if len({v["value"] for v in records}) > 1)
    for path, info in sorted(libraries.items()):
        directory, name = path.rsplit("/", 1)
        match = EGL_DRIVER.fullmatch(name)
        # Plain /system/lib/libEGL.so and GLES wrappers are not driver evidence.
        if not directory.endswith("/egl") or not match:
            continue
        role, suffix = match.groups()
        path_abi = "arm64" if directory.endswith("/lib64/egl") else "arm"
        if path_abi != abi:
            continue
        item = groups.setdefault((directory, suffix or ""), {
            "directory": directory, "suffix": suffix or "", "abi": abi,
            "libraries": {}, "invalid": []})
        if info is None or info["abi"] != abi:
            item["invalid"].append(path)
        else:
            item["libraries"][role] = path
    for item in groups.values():
        roles = set(item["libraries"])
        item["combined_candidate"] = "libGLES" in roles
        item["split_egl_gles2_candidate"] = {"libEGL", "libGLESv2"} <= roles
        item["gles1_present"] = "libGLESv1_CM" in roles
        item["matched_hint_keys"] = sorted(key for key, records in hints.items()
            if any(v["value"] == item["suffix"] for v in records))
        item["structurally_complete"] = not item["invalid"] and (
            item["combined_candidate"] or item["split_egl_gles2_candidate"])
    items = list(groups.values())
    complete = [item for item in items if item["structurally_complete"]]
    explicit = {v["value"] for key in ("persist.graphics.egl", "ro.hardware.egl")
                for v in hints.get(key, [])}
    matching = [item for item in complete if item["suffix"] in explicit]
    # Do not guess precedence, fallback, ANGLE, updated drivers or property service state.
    status = "REVIEW_REQUIRED"
    if abi in ("arm", "arm64") and not errors and not conflicts and len(complete) == 1:
        if not explicit or (len(explicit) == 1 and len(matching) == 1):
            status = "STATIC_EGL_DRIVER_GROUP_ONLY"
    return {"status": status, "abi": abi, "property_hints": hints,
            "conflicting_properties": conflicts, "groups": items,
            "complete_groups": len(complete), "explicit_hint_matches": len(matching),
            "errors": errors, "selected_driver": None,
            "runtime_selection_verified": False, "egl_initialized": False,
            "safe_to_flash": False}


MALI_KEYS = ("CONFIG_ARM64", "CONFIG_COMPAT", "CONFIG_MALI_T72X",
             "CONFIG_MALI_MIDGARD", "CONFIG_MALI_R21P0", "CONFIG_MALI_R28P0",
             "CONFIG_MALI_R29P0", "CONFIG_MALI_NO_MALI", "CONFIG_MALI_BIFROST",
             "CONFIG_MALI_PLATFORM_NAME", "CONFIG_DMA_SHARED_BUFFER",
             "CONFIG_SYNC_FILE", "CONFIG_MALI_DMA_FENCE", "CONFIG_ION",
             "CONFIG_ION_EXYNOS", "CONFIG_IOMMU_SUPPORT", "CONFIG_EXYNOS_IOMMU")


def gpu_dt_candidates(nodes):
    enabled, candidates = {}, []
    for path, props in nodes.items():
        parent = path.rsplit("/", 1)[0] or "/"
        status = strings(props.get("status", b""))
        enabled[path] = (not status or status in (["ok"], ["okay"])) and (
            path == "/" or enabled.get(parent, False))
        compatible = strings(props.get("compatible", b""))
        label = path.rsplit("/", 1)[-1].split("@", 1)[0].lower()
        if label not in ("gpu", "mali", "g3d") and not any(
                "mali" in value.lower() or "g3d" in value.lower() for value in compatible):
            continue
        candidates.append({"path": path, "compatible": compatible, "enabled": enabled[path],
                           "explicit_t72x": any(re.search(r"mali[-_,]?t72[0-9x]", v.lower())
                                               for v in compatible),
                           "resource_properties": sorted(key for key in
                               ("reg", "interrupts", "interrupts-extended", "clocks",
                                "clock-names", "power-domains", "iommus", "operating-points",
                                "operating-points-v2", "mali-supply", "gpu-supply")
                               if props.get(key))})
    return candidates


def mali_evidence(libraries, abi, kernel_config=None, dtb=None):
    """Compare observed inputs to the existing R800 T72x/r28 kernel recipe.

    Neither a Mali filename nor a DT compatible string establishes KBASE UAPI
    compatibility. No ioctl, GPU initialization or binary execution.
    """
    config = {key: (kernel_config or {}).get(key) for key in MALI_KEYS}
    errors, blockers, gpu_nodes = [], [], []
    versions = [key for key in ("CONFIG_MALI_R21P0", "CONFIG_MALI_R28P0", "CONFIG_MALI_R29P0")
                if config[key] in ("y", "m")]
    if kernel_config is None:
        blockers.append("Target kernel config not supplied")
    else:
        for key in ("CONFIG_MALI_T72X", "CONFIG_MALI_MIDGARD", "CONFIG_MALI_R28P0",
                    "CONFIG_DMA_SHARED_BUFFER", "CONFIG_SYNC_FILE", "CONFIG_ION",
                    "CONFIG_IOMMU_SUPPORT", "CONFIG_EXYNOS_IOMMU"):
            if config[key] != "y":
                blockers.append("R800 recipe requires built-in " + key)
        if versions != ["CONFIG_MALI_R28P0"]:
            blockers.append("Missing or ambiguous R800 kernel Mali release selection")
        if config["CONFIG_MALI_NO_MALI"] in ("y", "m"):
            blockers.append("Mali no-hardware mode enabled")
        if abi == "arm" and config["CONFIG_ARM64"] == "y" and config["CONFIG_COMPAT"] != "y":
            blockers.append("ARM32 userspace on ARM64 requires CONFIG_COMPAT")
    if dtb is None:
        blockers.append("Target DTB not supplied")
    else:
        try:
            gpu_nodes = gpu_dt_candidates(parse_dtb(dtb))
        except (ValueError, UnicodeError) as exc:
            errors.append(str(exc))
        active = [node for node in gpu_nodes if node["enabled"]]
        if len(active) != 1:
            blockers.append("Missing or ambiguous enabled GPU node")
        elif not active[0]["explicit_t72x"]:
            blockers.append("GPU compatible does not explicitly identify T72x")
    userspace = sorted(path for path, info in libraries.items()
                       if info and info["abi"] == abi and
                       path.rsplit("/", 1)[1].lower().startswith("libmali"))
    if not userspace:
        blockers.append("No same-ABI libMali candidate; combined EGL driver requires review")
    return {"status": "STATIC_MALI_RECIPE_EVIDENCE_ONLY" if not blockers and not errors
                      else "REVIEW_REQUIRED",
            "surfaceflinger_abi": abi, "kernel_config": config,
            "kernel_release_candidates": versions, "gpu_nodes": gpu_nodes,
            "userspace_candidates": userspace, "blockers": blockers, "errors": errors,
            "userspace_release_verified": False, "kbase_ioctl_abi_verified": False,
            "compat_ioctl_verified": False, "dma_buf_import_verified": False,
            "gpu_hardware_verified": False, "safe_to_flash": False}


def audit(root, init, vintf, inspect_elf, kernel_config=None, dtb=None):
    errors, services, libraries, nodes = [], [], {}, {}
    declared = {kind: [] for kind in HALS}
    for doc in vintf["files"].values():
        if doc["kind"] != "manifest" or doc["type"] != "device":
            continue
        for entry in doc["entries"]:
            for kind in HALS:
                if entry["name"] == "android.hardware.graphics." + kind:
                    declared[kind].append(entry)
    for service in init.get("graphics_services", []):
        item = {"name": service["name"], "path": service["executable"],
                "source": service["source"], "elf": None,
                "interfaces": [o["args"] for o in service["options"] if o["name"] == "interface"]}
        services.append(item)
        try:
            item["elf"] = executable(root, item["path"])
        except (OSError, ValueError) as exc:
            errors.append(item["name"] + ": " + str(exc))
    sf = [s for s in services if s["name"] == "surfaceflinger"]
    if len(sf) != 1 or not sf[0]["elf"]:
        errors.append("Missing or ambiguous inspected SurfaceFlinger service")
    scanned = total = 0
    exhausted = False
    for part in PARTITIONS:
        if exhausted:
            break
        for abi, lib in (("arm", "lib"), ("arm64", "lib64")):
            if exhausted:
                break
            for sub in ("", "/egl", "/hw"):
                directory = "/" + part + "/" + lib + sub
                try:
                    path = guest_path(root, directory)
                    names = []
                    for entry in path.iterdir():
                        scanned += 1
                        if scanned > MAX_SCAN:
                            raise ValueError("Graphics directory scan limit exceeded")
                        if LIB_PATTERN.fullmatch(entry.name):
                            names.append(entry.name)
                            if len(names) > MAX_LIBRARIES:
                                raise ValueError("Graphics directory candidate limit exceeded")
                    for name in sorted(names):
                        if len(libraries) >= MAX_LIBRARIES:
                            raise ValueError("Graphics library count limit exceeded")
                        guest = directory + "/" + name
                        libraries[guest] = None
                        try:
                            resolved = guest_path(root, guest)
                            length = resolved.lstat().st_size
                            if length > MAX_ELF or total + length > MAX_LIBRARY_BYTES:
                                raise ValueError("Graphics ELF byte budget exceeded")
                            data = read_regular(resolved, MAX_ELF)
                            total += len(data)
                            info = inspect_elf(data)
                            if (info["abi"] != abi or info["elf_type"] != "ET_DYN" or
                                    not info["has_dynamic"]):
                                raise ValueError("Graphics library is not compatible dynamic ELF")
                            libraries[guest] = {"abi": abi, "soname": info["soname"],
                                                "sha256": hashlib.sha256(data).hexdigest(),
                                                "bytes": len(data), "needed": info["needed"],
                                                "version_needs": info["version_needs"],
                                                "version_definitions": info["version_definitions"],
                                                "dynamic_symbol_count": info["dynamic_symbol_count"],
                                                "custom_search_path": info["custom_search_path"],
                                                "entrypoints": entrypoint_evidence(guest, info)}
                        except (OSError, ValueError) as exc:
                            errors.append(guest + ": " + str(exc))
                            if "budget exceeded" in str(exc):
                                exhausted = True
                                break
                except FileNotFoundError:
                    continue
                except (OSError, ValueError) as exc:
                    errors.append(directory + ": " + str(exc))
                    if "limit exceeded" in str(exc):
                        exhausted = True
                if exhausted:
                    break
    for name in DEVICES:
        try:
            nodes[name] = stat.S_ISCHR(guest_path(root, name).lstat().st_mode)
            if not nodes[name]:
                errors.append(name + ": not a character device")
        except FileNotFoundError:
            nodes[name] = False
        except (OSError, ValueError) as exc:
            nodes[name] = False
            errors.append(name + ": " + str(exc))
    candidates = {abi: {"egl": [], "gles2": [], "mali": [], "legacy_hal": []}
                  for abi in ("arm", "arm64")}
    for path, info in libraries.items():
        if not info:
            continue
        name = path.rsplit("/", 1)[1]
        items = candidates[info["abi"]]
        if name.startswith("libEGL"):
            items["egl"].append(path)
        if name.startswith("libGLESv2"):
            items["gles2"].append(path)
        if name.lower().startswith("libmali"):
            items["mali"].append(path)
        if name.startswith(("gralloc.", "hwcomposer.")):
            items["legacy_hal"].append(path)
    sf_abi = sf[0]["elf"]["architecture"] if len(sf) == 1 and sf[0]["elf"] else None
    driver_groups = egl_driver_candidates(root, libraries, sf_abi)
    missing = [kind for kind in HALS if not declared[kind]]
    if sf_abi and not all(candidates[sf_abi][kind] for kind in ("egl", "gles2")):
        errors.append("SurfaceFlinger ABI has incomplete EGL/GLES candidate inventory")
    return {"status": "STATIC_GRAPHICS_INVENTORY_ONLY" if not errors and not missing else "REVIEW_REQUIRED",
            "surfaceflinger_abi": sf_abi, "services": services, "declared_hals": declared,
            "missing_hal_declarations": missing, "libraries": libraries, "candidates": candidates,
            "egl_driver_groups": driver_groups,
            "hwc_stride_evidence": hwc_stride_evidence(root),
            "mapper_2_1_evidence": mapper_2_1_evidence(declared["mapper"], libraries, sf_abi),
            "mapper_factory_evidence": mapper_factory_evidence(libraries, sf_abi),
            "entrypoint_evidence": graphics_entrypoints(libraries, driver_groups, sf_abi),
            "mali_evidence": mali_evidence(libraries, sf_abi, kernel_config, dtb),
            "device_nodes": nodes, "kernel_config": None if kernel_config is None else
            {key: kernel_config.get(key) for key in KERNEL_KEYS},
            "errors": errors, "egl_initialized": False, "gpu_driver_compatible": False,
            "hal_registration_verified": False, "surfaceflinger_started": False,
            "display_output_verified": False, "safe_to_flash": False}
