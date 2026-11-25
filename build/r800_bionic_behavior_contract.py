"""Guest-reported functional Bionic checks, separate from property markers."""
PREFIX=b"r800-bionic: "
MEMORY=PREFIX+b"memory=PASS"
TLS=PREFIX+b"pthread-tls=PASS"
LINKER=PREFIX+b"libdl-libm=PASS missing-symbol=PASS"
PROVIDERS=("/system/lib64/bootstrap/libm.so","/system/lib64/libm.so",
           "/apex/com.android.runtime/lib64/bionic/libm.so")
DOMAIN=b"r800-property-client: domain=u:r:galwear_property_client:s0 protocol=2"
FIRST_SET=b"r800-property-client: socket-set=PASS read=ready"


def markers(provider):
    if provider not in PROVIDERS:
        raise ValueError("Unexpected Bionic libm provider")
    return [MEMORY,TLS,PREFIX+b"libm-provider="+provider.encode("ascii"),LINKER]


def inspect(log):
    lines=log.replace(b"\r\n",b"\n").splitlines()
    found=[line for line in lines if line.startswith(PREFIX)]
    if len(found)!=4:
        raise ValueError("Missing or duplicate Bionic diagnostics")
    providers=[p for p in PROVIDERS if found==markers(p)]
    if len(providers)!=1:
        raise ValueError("Unexpected Bionic diagnostic sequence/provider")
    if lines.count(DOMAIN)!=1 or lines.count(FIRST_SET)!=1 or not (
            lines.index(DOMAIN)<lines.index(found[0])<lines.index(found[-1])<lines.index(FIRST_SET)):
        raise ValueError("Bionic diagnostics outside client execution window")
    return {"bionic_memory_reported":True,"bionic_pthread_tls_reported":True,
            "bionic_libdl_libm_reported":True,"bionic_missing_symbol_reported":True,
            "bionic_libm_provider":providers[0],
            "all_runtime_stubs_excluded":False}


def verify_provider(evidence,resolution):
    client=resolution["executables"]["/system/bin/galwear_property_client"]
    providers={e["resolved"] for e in client["edges"] if e["needed"]=="libm.so"}
    if providers!={evidence["bionic_libm_provider"]}:
        raise ValueError("Observed Bionic libm provider differs from selected ELF graph")
