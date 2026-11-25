# ABOX firmware pair and callback drain (NON-RELEASE)
Base 2d60adf646ef58280619f27b9337c0a95ff5295c, all six CI checks passed. Request DRAM before publishing
SRAM; missing DRAM consumes the same bounded retry path. Release failed
SRAM image. Fix duplicate list insertion when revisiting extra firmware.
Stop new firmware submissions, cancel delayed retries, wait for any
in-flight callback during shutdown/remove/probe failure. Firmware mutex
protects submission and callback; completion wait outside mutex.
Source-layout and offline tests pending. Existing singleton driver
assumption retained; full driver teardown, notifier/workqueue lifetimes,
PM races, missing optional extra firmware and physical boot unverified.
Firmware callback may block on request_firmware; no bounded shutdown
latency guaranteed. No DSP power policy changes. safe_to_flash=false.
