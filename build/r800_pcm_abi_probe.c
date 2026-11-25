/* Compile with the same NDK/ABI as tinyalsa. Never execute on host/device. */
#include <stdint.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <sound/asound.h>

__attribute__((used, section(".r800_pcm_abi")))
const uint32_t r800_pcm_abi[] = {
    sizeof(void *),
    sizeof(snd_pcm_uframes_t),
    sizeof(struct snd_pcm_sync_ptr),
    sizeof(struct snd_pcm_mmap_status),
    sizeof(struct snd_pcm_mmap_control),
    offsetof(struct snd_pcm_sync_ptr, flags),
    offsetof(struct snd_pcm_sync_ptr, s.status),
    offsetof(struct snd_pcm_sync_ptr, c.control),
    offsetof(struct snd_pcm_mmap_status, hw_ptr),
    offsetof(struct snd_pcm_mmap_control, appl_ptr),
    offsetof(struct snd_pcm_mmap_control, avail_min),
    sizeof(struct snd_xferi),
    offsetof(struct snd_xferi, result),
    offsetof(struct snd_xferi, buf),
    offsetof(struct snd_xferi, frames),
    SNDRV_PCM_IOCTL_SYNC_PTR,
    SNDRV_PCM_IOCTL_READI_FRAMES,
    SNDRV_PCM_IOCTL_WRITEI_FRAMES,
    SNDRV_PCM_SYNC_PTR_HWSYNC,
    SNDRV_PCM_SYNC_PTR_APPL,
    SNDRV_PCM_SYNC_PTR_AVAIL_MIN,
};
