# Additional configuration syntax review

Baseline c8274a6a0a7b72f56348de8907d220b191310dac: 7/7 workflows.
GPS host run 45799286274 job 139837964312 confirmed eight
extended readiness tests, real verifier case and offline gate.

Opt-in --review-configs on r800_tzlite_legacy_image_scope.py.
Review four exact regular paths from the same verified snapshot:
nsswitch.conf, hosts, resolv.conf and sensor.xml. Bind raw
bytes to existing inventory SHA-256. Strict bounded syntax
subset; unknown NSS providers/actions, resolver directives,
XML declarations/entities and excessive structure require
review. Report counts and NSS provider candidates, no raw
hostnames, addresses or XML values. No DNS/network requests.
No semantic, NSS library availability or runtime claim.
Separate report digest; existing extended review manifest
unchanged. Configs remain excluded from staging. Nine unit
tests and one real ext4 case pending CI. Original donor absent.
safe_to_flash=false.
