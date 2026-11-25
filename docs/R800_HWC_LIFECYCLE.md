# R800 HWC lifecycle (NON-RELEASE)

Base: 110d7a5d9e7e69f19c3ada1d46891852aa56a9a6.
Previously close was a no-op, workers never terminated, thread creation
errors were ignored and failed framebuffer/gralloc setup leaked handles.
Close now signals both workers and joins before unmap, FD close, dlclose
and lock destruction. Open rejects an unavailable framebuffer and unwinds
partial initialization, including the first thread if the second fails.
The HAL output pointer remains NULL until both workers start.

Host tests compile the real stop function with pthread fixtures and repeat
100 partial/full shutdown scenarios. These are not full HAL builds.
Close assumes all external HAL calls are quiesced by its owner and does
not make callback replacement/unregistration safe against in-flight calls.
A self-close returns EDEADLK. A stuck kernel ioctl or framework callback
can still prevent join; no unsafe forced cancellation or panel reset.
Historical initial wake/restart mode policy is unchanged; framebuffer
release behavior and composer reopen on actual hardware remain unverified.
safe_to_flash=false. Fork only.
