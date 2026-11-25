# SM-R800 HWC TE/VSync recovery (NON-RELEASE)

Base: da7b7d5c903d64aae9d8952a8373af3fcc4428bb. Stale or malformed TE values and repeated poll
events previously could starve timer callbacks or shift their time grid.
Validate the kernel timestamp against monotonic time (2 s maximum age),
fall back to the next bounded timer slot, handle EINTR, and stop polling
a dead FD. Reset the TE baseline on enable epoch changes. Read the
callback registration under the mutex, invoke framework code outside it.

Host tests compile the extracted production timing functions using cc.
They do not compile the full Android HAL or emulate the kernel poll ABI.
No hardware reset, suspend policy change or automatic composer restart.
A lost TE FD remains timer-only for that instance. Callback unregister
and in-flight ownership still rely on the historical process-lifetime
contract; thread shutdown and full SurfaceFlinger restart are open.
Exact-head CI and real-device TE evidence required. safe_to_flash=false.
