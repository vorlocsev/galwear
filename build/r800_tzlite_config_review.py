"""Conservative syntax review of selected legacy configs, never deploy or resolve DNS."""
import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET

from r800_extract_ext4 import command
from r800_tzlite_image_xattrs import check_diagnostics
from r800_tzlite_manifest import read_file
from r800_tizen_gnss_preflight import CONFIG_LIMIT

SUPPORTED=("/etc/nsswitch.conf","/etc/hosts","/etc/resolv.conf","/usr/etc/sensor.xml")
MAX_LINES=4096
MAX_LINE=4096
HOST=re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.?")
LABEL=re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def hostname(value):
    if not HOST.fullmatch(value) or not all(LABEL.fullmatch(v) for v in value.rstrip(".").split(".")):
        raise ValueError("Unsupported hostname")


def text(raw):
    if not 0<len(raw)<=CONFIG_LIMIT or b"\0" in raw:
        raise ValueError("Unsupported configuration size or encoding")
    value=raw.decode("utf-8")
    if any(ord(c)<32 and c not in "\n\r\t" or ord(c)==127 for c in value):
        raise ValueError("Unsupported configuration control character")
    return value


def lines(raw):
    data=text(raw).splitlines()
    if len(data)>MAX_LINES or any(len(v)>MAX_LINE for v in data):
        raise ValueError("Configuration line budget exceeded")
    return [line for v in data if (line:=v.split("#",1)[0].strip())]


def nsswitch(raw):
    databases=set()
    providers=set()
    basic={}
    for line in lines(raw):
        if ":" not in line:
            raise ValueError("Missing NSS separator")
        name,body=(v.strip() for v in line.split(":",1))
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}",name) or name in databases:
            raise ValueError("Duplicate or unsupported NSS database")
        databases.add(name)
        # Deliberately reject action blocks and unknown providers pending review.
        tokens=body.split()
        if not tokens or any(v not in ("files","dns") for v in tokens):
            raise ValueError("Unsupported NSS provider or action")
        providers.update(tokens)
        if name in ("passwd","group","hosts"):
            basic[name]=tokens
    if not {"passwd","group","hosts"}.issubset(databases):
        raise ValueError("Missing basic NSS databases")
    return {"database_count":len(databases),"provider_candidates":sorted(providers),
            "basic_database_providers":basic,"other_database_count":len(databases)-len(basic)}


def hosts(raw):
    count=0
    for line in lines(raw):
        fields=line.split()
        if not 2<=len(fields)<=64:
            raise ValueError("Invalid hosts record")
        ipaddress.ip_address(fields[0])
        for value in fields[1:]:
            hostname(value)
        count+=1
    if not count:
        raise ValueError("Empty hosts inventory")
    return {"record_count":count}


def resolv(raw):
    count=0
    seen=set()
    for line in lines(raw):
        fields=line.split()
        key,*values=fields
        if key=="nameserver" and len(values)==1:
            ipaddress.ip_address(values[0])
            count+=1
            if count>3:
                raise ValueError("Nameserver budget exceeded")
        elif key in ("search","domain") and key not in seen and (
                1<=len(values)<=6 if key=="search" else len(values)==1):
            if {"search","domain"}&seen:
                raise ValueError("Conflicting resolver domain directives")
            for value in values:
                hostname(value)
            seen.add(key)
        else:
            raise ValueError("Unsupported resolver directive")
    if not count:
        raise ValueError("Missing nameserver")
    return {"nameserver_count":count,"domain_directive_count":len(seen)}


def sensor_xml(raw):
    value=text(raw)
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)",value,re.I):
        raise ValueError("XML declaration requires review")
    root=ET.fromstring(value)
    stack=[(root,0)]
    count=0
    while stack:
        node,depth=stack.pop()
        count+=1
        if count>4096 or depth>32 or len(node.attrib)>64:
            raise ValueError("XML structure budget exceeded")
        stack.extend((child,depth+1) for child in node)
    return {"element_count":count}


PARSERS=dict(zip(SUPPORTED,(nsswitch,hosts,resolv,sensor_xml)))


def inspect_snapshot(resolver,inventory):
    records={}
    for path in SUPPORTED:
        item=inventory["entries"].get(path)
        if item is None or item.get("kind")!="regular" or item.get("links")!=1 or "sha256" not in item:
            records[path]={"status":"NOT_TESTED_REGULAR_INPUT_REQUIRED"}
            continue
        size=item["bytes"]
        result={"sha256":item["sha256"],"bytes":size}
        if not 0<size<=CONFIG_LIMIT:
            records[path]=dict(result,status="REVIEW_REQUIRED",reason="CONFIG_SIZE_REVIEW")
            continue
        member=resolver.scratch/"config-review-member"
        if member.exists() or member.is_symlink():
            raise ValueError("Unexpected private configuration member")
        try:
            reply=command(resolver.tool,resolver.snapshot,
                          "dump <%d> config-review-member"%item["inode"],cwd=resolver.scratch)
            check_diagnostics(reply.stderr)
            raw=read_file(member,CONFIG_LIMIT,capture=True)[1]
            if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=item["sha256"]:
                raise ValueError("Config review inventory hash mismatch")
            try:
                detail=PARSERS[path](raw)
                records[path]=dict(result,status="STATIC_SYNTAX_CANDIDATE_ONLY",detail=detail)
            except (ValueError,ET.ParseError):
                # Never return raw configuration values or parser exception text.
                records[path]=dict(result,status="REVIEW_REQUIRED",reason="CONFIG_SYNTAX_OR_SCOPE_REVIEW")
        finally:
            member.unlink(missing_ok=True)
    return {"schema":"r800-tzlite-config-review-v1","status":"STATIC_CONFIG_REVIEW_ONLY",
            "files":records,"problems":[path for path,rec in records.items()
                if rec["status"]!="STATIC_SYNTAX_CANDIDATE_ONLY"],
            "nss_runtime_verified":False,"configuration_semantics_verified":False,
            "staging_authorized":False,"runtime_verified":False,"safe_to_flash":False}
