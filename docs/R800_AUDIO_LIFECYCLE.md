# R800 Audio lifecycle (NON-RELEASE)

Base 622d886158c00067b9104d98d1ff54b2f44a5ada, 6/6 workflows passed. A device close with either stream
still registered now returns -EBUSY, leaving ownership and HFP state
unchanged; caller must close streams and retry. Device lock is held
across stream standby, detach and destruction; HFP/replacement cannot
interleave. Null/foreign stream handles are rejected. Stream mutex
initialization failures unwind without publishing handles. Device open
clears output pointer before validation.

Host harness compiles actual three close functions and exercises early
close, foreign/null stream, individual teardown, successful final close.
Static regression checks stream initialization rollback.

Framework must quiesce all stream/device entrypoints before destruction;
no raw-pointer API can guard calls made after free. Framework behavior
on -EBUSY, driver hangs, actual audioserver restart and ABOX remain
untested. No kernel changes or hardware testing. safe_to_flash=false.
