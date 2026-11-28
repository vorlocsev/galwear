#!/usr/bin/env python3
"""Offline capacity estimate for the existing R800 development layout.

No device discovery, partition writes, migration, deletion or filesystem
creation. Operator-provided capacity observations are not authenticated.
File allocation is a lower bound plus explicit reserves, not an installer
or a guarantee of filesystem allocation success.
"""
from pathlib import PurePosixPath
from r800_boot_candidate import PARTITION, HEADER, DT_OFFSET, DT_SIZE, SIG
from r800_extract_super import require

VENDOR="r800-android/vendor.img"
MAX_BYTES=2**40
BLOCK_SIZES=(1024,2048,4096)
SCHEMA="galwear-r800-capacity-observation-v1"


def integer(value,minimum,maximum):
    return type(value) is int and minimum<=value<=maximum


def round_up(n,block):
    return ((n+block-1)//block)*block


def placement(files,dirs):
    require(VENDOR in files,"Vendor image missing")
    result={"p15":{VENDOR:files[VENDOR]["bytes"]},"p17":{}}
    for path,row in files.items():
        if path.startswith("r800dev/"):
            result["p17"][path]=row["bytes"]
        else:
            require(path==VENDOR or path.startswith("vendor/"),
                    "Unknown development storage path: "+path)
    require("r800dev/android/system.img" in result["p17"],"System image missing")
    directory_sets={}
    for part,rows in result.items():
        require(all(integer(n,1,MAX_BYTES) for n in rows.values()),"Invalid placement size")
        parents={p.as_posix() for path in rows for p in PurePosixPath(path).parents
                 if p.as_posix()!="."}
        if part=="p17":
            require(all(p.startswith("r800dev/") for p in dirs),"Unexpected mountpoint path")
            for path in dirs:
                parents.add(path)
                parents.update(p.as_posix() for p in PurePosixPath(path).parents
                               if p.as_posix()!=".")
        directory_sets[part]=parents
    return result,directory_sets


def observation(value):
    require(isinstance(value,dict) and set(value)=={"schema","model","scope","partitions"} and
            value["schema"]==SCHEMA and value["model"]=="SM-R800" and
            value["scope"]=="OPERATOR_REPORTED_READ_ONLY",
            "Expected explicit SM-R800 read-only capacity observation")
    parts=value["partitions"]
    require(isinstance(parts,dict) and set(parts)=={"p15","p17"},"Only p15 and p17 are eligible")
    for name,row in parts.items():
        require(isinstance(row,dict) and set(row)=={"block_size","available_blocks",
                "available_inodes","reserve_bytes","reserve_inodes"},"Invalid observation: "+name)
        block=row["block_size"]
        require(type(block) is int and block in BLOCK_SIZES and
                integer(row["available_blocks"],0,MAX_BYTES//block) and
                integer(row["available_inodes"],0,2**32-1) and
                integer(row["reserve_bytes"],block,MAX_BYTES) and
                integer(row["reserve_inodes"],1,2**32-1),"Invalid capacity or reserve: "+name)
    return parts


def estimate(files,dirs,kernel_files,observed=None):
    rows,parents=placement(files,dirs)
    capacities=observation(observed) if observed is not None else None
    result={}
    for name,members in rows.items():
        item={"logical_file_bytes":sum(members.values()),"files":len(members),
              "directories":len(parents[name]),"minimum_new_inodes":len(members)+len(parents[name]),
              "status":"CAPACITY_NOT_MEASURED"}
        if capacities is not None:
            c=capacities[name]
            b=c["block_size"]
            allocated=sum(round_up(n,b) for n in members.values())+len(parents[name])*b
            required=allocated+round_up(c["reserve_bytes"],b)
            required_inodes=item["minimum_new_inodes"]+c["reserve_inodes"]
            available=c["available_blocks"]*b
            item.update(block_size=b,allocation_lower_bound_bytes=allocated,
                        reserve_bytes=round_up(c["reserve_bytes"],b),
                        estimated_required_bytes=required,reported_available_bytes=available,
                        reported_available_inodes=c["available_inodes"],
                        estimated_required_inodes=required_inodes,
                        remaining_bytes=available-required,
                        remaining_inodes=c["available_inodes"]-required_inodes,
                        status="ESTIMATE_FITS_REPORTED_CAPACITY" if
                        available>=required and c["available_inodes"]>=required_inodes
                        else "ESTIMATE_EXCEEDS_REPORTED_CAPACITY")
        result[name]=item
    image=kernel_files["development-boot/Image"]["bytes"]
    dtb=kernel_files["development-boot/r800.dtb"]["bytes"]
    require(integer(image,64,PARTITION) and dtb==DT_SIZE,"Invalid boot component sizes")
    minimum=HEADER+round_up(image,HEADER)+DT_OFFSET+DT_SIZE+SIG
    return {"schema":"galwear-r800-storage-estimate-v1",
            "status":"STORAGE_ESTIMATE_ONLY",
            "boot":{"historical_budget_bytes":PARTITION,"minimum_container_bytes":minimum,
                    "remaining_minimum_budget_bytes":PARTITION-minimum,
                    "status":"STATIC_MINIMUM_FITS" if minimum<=PARTITION else "STATIC_MINIMUM_EXCEEDS"},
            "partitions":result,"excluded_provenance_bytes":sum(
                r["bytes"] for n,r in files.items() if n.startswith("vendor/")),
            "excluded_kernel_evidence_bytes":sum(r["bytes"] for n,r in kernel_files.items()
                if n not in ("development-boot/Image","development-boot/r800.dtb")),
            "preserved_partitions":["p16","p18"],
            "userdata_and_persistent_state_budgeted":False,
            "capacity_observation_authenticated":False,
            "filesystem_overhead_fully_modeled":False,
            "partition_size_verified":False,"safe_to_flash":False}
