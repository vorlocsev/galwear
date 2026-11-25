#!/usr/bin/env python3
"""Sequential AOSP property-service experiment. No flash, release or hardware.

Build phase needs a clean, disposable, already synced AOSP tree.
Boot phase needs explicit library choices and an accepted property virt kernel.
Each phase uses a new output directory; failed stages stop the pipeline.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

from r800_android_rootfs_preflight import snapshot
from r800_android_init_rootfs import unique_object
from r800_qemu_guest_abi import verify_baseline
from r800_qemu_property_kernel import verify_config
from r800_qemu_selinux_policy import verify_prepolicy

TOOLS = Path(__file__).resolve().parent
REPO = TOOLS.parent
MAX_REPORT = 4*1024*1024


def read_report(path):
    result = json.loads(snapshot(path, MAX_REPORT), object_pairs_hook=unique_object)
    if not isinstance(result, dict):
        raise ValueError("Invalid stage report: " + str(path))
    return result


def require_report(path, status, safe=True):
    r = read_report(path)
    if r.get("status") != status or (safe and r.get("safe_to_flash") is not False):
        raise ValueError("Unexpected stage status: " + str(path))
    return r


def resolved_output(build, name):
    raw = snapshot(build / (name+"-out-path.txt"), 4096).decode("utf-8").strip()
    path = Path(raw)
    base = (build/"aosp-out").resolve(strict=True)
    if not path.is_absolute() or not path.is_dir() or path.resolve() != path:
        raise ValueError("Invalid resolved build path")
    if not path.is_relative_to(base):
        raise ValueError("Build output escapes dedicated tree")
    return path


class Pipeline:
    def __init__(self, out, phase, source_commit=None):
        self.out = out
        self.phase = phase
        self.source_commit = source_commit
        self.steps = []
        self.status = "RUNNING"
        out.mkdir(parents=False, exist_ok=False)
        self.save()

    def save(self):
        report = {"status": self.status, "phase": self.phase, "steps": self.steps,
                  "source_commit": self.source_commit,
                  "safe_to_flash": False, "device_contacted": False,
                  "android_init_started": False,
                  "property_service_started": self.status in ("VIRT_PROPERTY_SERVICE_PIPELINE_ONLY",
                                                              "VIRT_EXT4_PROPERTY_PIPELINE_ONLY")}
        tmp = self.out/"pipeline.json.tmp"
        tmp.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
        tmp.replace(self.out/"pipeline.json")

    def step(self, name, command, evidence=None, expected=None, safe=True):
        item = {"name": name, "status": "RUNNING", "log": name+".log"}
        self.steps.append(item)
        self.save()
        started = time.monotonic()
        log = self.out/item["log"]
        print("stage:", name, flush=True)
        try:
            with log.open("xb") as stream:
                subprocess.run([str(x) for x in command], cwd=REPO,
                               stdin=subprocess.DEVNULL, stdout=stream,
                               stderr=subprocess.STDOUT, check=True)
            if evidence is not None:
                report = require_report(evidence, expected, safe)
                item["evidence"] = str(evidence)
                item["evidence_status"] = report["status"]
                item["evidence_sha256"] = hashlib.sha256(snapshot(evidence, MAX_REPORT)).hexdigest()
            item["status"] = "PASS"
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
            item["status"] = "FAILED"
            item["reason"] = str(exc)[:1000] or type(exc).__name__
            self.status = "REJECT"
            raise
        finally:
            item["elapsed_seconds"] = round(time.monotonic()-started, 3)
            self.save()

    def py(self, name, script, args, report, status, safe=True):
        self.step(name, [sys.executable, TOOLS/script, *args, "--report", report],
                  report, status, safe)

    def shell(self, name, script, args, evidence, status, safe=True):
        self.step(name, ["bash", TOOLS/script, *args], evidence, status, safe)


def build_phase(p, a):
    root, out = a.aosp_root, p.out
    runtime = out/"runtime"
    service = out/"service"
    stock = out/"stock"
    fixture = out/"fixture"
    p.shell("01-runtime", "r800_aosp_runtime_build.sh", [root, runtime, a.jobs],
            runtime/"runtime-extraction.json", "ANDROID_RUNTIME_EXTRACTED_STATIC_ONLY")
    p.shell("02-init-service", "r800_aosp_init_service_build.sh",
            [root, service, runtime/"runtime-root"], service/"init-dependencies.json",
            "INIT_DEPENDENCY_CANDIDATES_ONLY")
    p.shell("03-stock-policy", "r800_aosp_sepolicy_build.sh", [root, stock],
            stock/"sepolicy-audit.json", "ANDROID_SEPOLICY_STATIC_COMPATIBILITY_ONLY")
    p.shell("04-fixture-policy", "r800_aosp_galwear_policy_build.sh", [root, fixture],
            fixture/"fixture-policy-audit.json", "GALWEAR_CLIENT_POLICY_STATIC_ONLY")
    for index, mode in enumerate(("transition", "relabel", "service"), 5):
        dest = out/("probe-"+mode)
        p.shell(f"{index:02d}-probe-{mode}", "r800_aosp_selinux_transition_build.sh",
                [root, dest, mode], dest/"initramfs-evidence.json",
                "NON_RELEASE_INITRAMFS_SPEC_ONLY", False)
    for index, mode, src in ((8, "preflight", "android-rootfs-preflight.c"),
                             (9, "stock-load", "android-stock-policy-probe.c")):
        binary = out/(mode+"-init")
        p.step(f"{index:02d}-compile-{mode}", ["aarch64-linux-gnu-gcc", "-std=c11",
            "-Wall", "-Wextra", "-Werror", "-O2", "-static", REPO/"src/initramfs"/src,
            "-o", binary])
        p.py(f"{index:02d}-spec-{mode}", "r800_initramfs_spec.py",
             ["--init", binary, "--list", out/(mode+".list")],
             out/(mode+"-compile.json"), "NON_RELEASE_INITRAMFS_SPEC_ONLY", False)
    # Paths are obtained from the actual build, never guessed from target name.
    for name in ("service", "stock", "fixture"):
        resolved_output(out/name, "product")
    for name in ("stock", "fixture"):
        resolved_output(out/name, "host")
    p.status = "AOSP_PROPERTY_PIPELINE_BUILD_ONLY"


def verify_build(root, source_commit):
    report = require_report(root/"pipeline.json", "AOSP_PROPERTY_PIPELINE_BUILD_ONLY")
    if report.get("source_commit") != source_commit:
        raise ValueError("Build pipeline source commit differs from current checkout")
    steps = report.get("steps", [])
    contracts = {
        "01-runtime": ("runtime/runtime-extraction.json", "ANDROID_RUNTIME_EXTRACTED_STATIC_ONLY"),
        "02-init-service": ("service/init-dependencies.json", "INIT_DEPENDENCY_CANDIDATES_ONLY"),
        "03-stock-policy": ("stock/sepolicy-audit.json", "ANDROID_SEPOLICY_STATIC_COMPATIBILITY_ONLY"),
        "04-fixture-policy": ("fixture/fixture-policy-audit.json", "GALWEAR_CLIENT_POLICY_STATIC_ONLY"),
        "05-probe-transition": ("probe-transition/initramfs-evidence.json", "NON_RELEASE_INITRAMFS_SPEC_ONLY"),
        "06-probe-relabel": ("probe-relabel/initramfs-evidence.json", "NON_RELEASE_INITRAMFS_SPEC_ONLY"),
        "07-probe-service": ("probe-service/initramfs-evidence.json", "NON_RELEASE_INITRAMFS_SPEC_ONLY"),
        "08-compile-preflight": None,
        "08-spec-preflight": ("preflight-compile.json", "NON_RELEASE_INITRAMFS_SPEC_ONLY"),
        "09-compile-stock-load": None,
        "09-spec-stock-load": ("stock-load-compile.json", "NON_RELEASE_INITRAMFS_SPEC_ONLY"),
    }
    expected = list(contracts)
    if [s.get("name") for s in steps] != expected or any(s.get("status") != "PASS" for s in steps):
        raise ValueError("Incomplete source build pipeline")
    for step in steps:
        contract = contracts[step["name"]]
        if contract is None:
            continue
        relative, expected_status = contract
        path = Path(step["evidence"])
        if path != root/relative or step.get("evidence_status") != expected_status:
            raise ValueError("Build stage evidence contract mismatch: " + step["name"])
        if not path.is_absolute() or not path.resolve(strict=True).is_relative_to(root):
            raise ValueError("Build stage evidence escapes build directory")
        if hashlib.sha256(snapshot(path, MAX_REPORT)).hexdigest() != step["evidence_sha256"]:
            raise ValueError("Build stage evidence changed: " + step["name"])
        require_report(path, expected_status, safe=expected_status != "NON_RELEASE_INITRAMFS_SPEC_ONLY")


def boot_phase(p, a):
    b, o = a.build_root, p.out
    verify_build(b, p.source_commit)
    digest = verify_baseline(a.baseline, a.kernel)
    verify_config(a.config_evidence, digest)
    verify_prepolicy(a.prepolicy, digest)
    product = resolved_output(b/"service", "product")
    stock = resolved_output(b/"stock", "product")
    fixture = resolved_output(b/"fixture", "product")
    stock_checkfc = resolved_output(b/"stock", "host")/"bin/checkfc"
    fixture_tools = resolved_output(b/"fixture", "host")/"bin"
    runtime = b/"runtime/runtime-root"
    staged = o/"staged"
    preflight = b/"preflight-init"
    rootfs_archive = o/"preflight.cpio"
    common = ["--kernel", a.kernel, "--baseline", a.baseline,
              "--config-evidence", a.config_evidence]
    layout = ["--staged", staged, "--product-out", stock]
    p.py("01-stage-rootfs", "r800_android_init_rootfs.py",
         ["--product-out", product, "--runtime-root", runtime, "--choices", a.choices,
          "--out", staged], o/"layout.json", "INIT_EXPERIMENTAL_ROOTFS_STAGED_ONLY")
    p.py("02-pack-rootfs", "r800_android_rootfs_preflight.py",
         [*layout, "--init", preflight, "--archive", rootfs_archive],
         o/"preflight-archive.json", "ANDROID_ROOTFS_PREFLIGHT_ARCHIVE_ONLY")
    rootfs_report = o/"preflight-boot.json"
    p.py("03-boot-rootfs", "r800_qemu_rootfs_preflight.py",
         [*layout, *common, "--init", preflight, "--archive", rootfs_archive,
          "--prepolicy", a.prepolicy, "--out-dir", o/"preflight-boot"],
         rootfs_report, "VIRT_ANDROID_ROOTFS_PREFLIGHT_ONLY")
    stock_report = o/"stock-policy-boot.json"
    p.py("04-load-stock", "r800_qemu_android_stock_policy.py",
         [*common, "--init", b/"stock-load-init", "--compile-evidence", b/"stock-load-compile.json",
          "--rootfs-report", rootfs_report, "--rootfs-archive", rootfs_archive,
          "--product-out", stock, "--checkfc", stock_checkfc, "--out-dir", o/"stock-policy-boot"],
         stock_report, "VIRT_ANDROID_STOCK_POLICY_LOAD_ONLY")
    transition = o/"transition-boot.json"
    p.py("05-transition", "r800_qemu_selinux_transition.py",
         [*common, "--init", b/"probe-transition/init",
          "--compile-evidence", b/"probe-transition/initramfs-evidence.json",
          "--stock-policy-report", stock_report, "--product-out", stock,
          "--checkfc", stock_checkfc, "--out-dir", o/"transition-boot"],
         transition, "VIRT_ANDROID_DIAGNOSTIC_INIT_DOMAIN_ONLY")
    p.py("06-relabel-policy-gate", "r800_rootfs_relabel_policy_gate.py",
         ["--product-out", stock, "--checkfc", stock_checkfc],
         o/"relabel-policy-gate.json", "ROOTFS_RELABEL_POLICY_PREREQUISITES_ONLY")
    relabel = o/"relabel-boot.json"
    p.py("06-relabel", "r800_qemu_rootfs_relabel.py",
         [*layout, *common, "--preflight-init", preflight, "--init", b/"probe-relabel/init",
          "--compile-evidence", b/"probe-relabel/initramfs-evidence.json",
          "--rootfs-report", rootfs_report, "--rootfs-archive", rootfs_archive,
          "--stock-policy-report", stock_report, "--transition-report", transition,
          "--checkfc", stock_checkfc, "--out-dir", o/"relabel-boot"],
         relabel, "VIRT_ANDROID_ROOTFS_RELABEL_ONLY")
    p.py("07-property-service", "r800_qemu_property_service.py",
         [*common, "--staged", staged, "--stock-product-out", stock,
          "--fixture-product-out", fixture, "--preflight-init", preflight,
          "--init", b/"probe-service/init",
          "--compile-evidence", b/"probe-service/initramfs-evidence.json",
          "--stock-relabel-report", relabel, "--checkfc", fixture_tools/"checkfc",
          "--analyze", fixture_tools/"sepolicy-analyze", "--out-dir", o/"service-boot"],
         o/"service-boot.json", "VIRT_GALWEAR_ORIGINAL_PROPERTY_SERVICE_ONLY")
    p.status = "VIRT_PROPERTY_SERVICE_PIPELINE_ONLY"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="phase", required=True)
    build = sub.add_parser("build")
    build.add_argument("--aosp-root", type=Path, required=True)
    build.add_argument("--jobs", type=int, default=4, choices=range(1, 100))
    boot = sub.add_parser("boot")
    for name in ("build-root", "choices", "kernel", "baseline", "config-evidence", "prepolicy"):
        boot.add_argument("--"+name, type=Path, required=True)
    for part in (build, boot):
        part.add_argument("--out", type=Path, required=True)
    a = parser.parse_args()
    # Child recipes use absolute paths regardless of the caller's cwd.
    for key, value in vars(a).items():
        if isinstance(value, Path):
            if value.is_symlink():
                parser.error("Symlinked input/output: "+key)
            setattr(a, key, value.resolve(strict=key != "out"))
    p = None
    try:
        if a.phase == "build" and a.out.is_relative_to(a.aosp_root):
            raise ValueError("Output must be outside disposable AOSP checkout")
        if a.out.is_relative_to(REPO):
            raise ValueError("Output must be outside repository")
        source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
        if subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO, text=True).strip():
            raise ValueError("Clean GalWear checkout required")
        p = Pipeline(a.out, a.phase, source_commit)
        (build_phase if a.phase == "build" else boot_phase)(p, a)
        p.save()
        return 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        if p is not None:
            if p.status != "REJECT":
                p.steps.append({"name": "pipeline-validation", "status": "FAILED",
                                "reason": str(exc)[:1000] or type(exc).__name__})
            p.status = "REJECT"
            p.save()
        print("REJECT:", exc, file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
