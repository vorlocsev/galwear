#ifndef R800_DECON_ABI_H
#define R800_DECON_ABI_H

#include <stddef.h>
#include <stdint.h>
#include <sys/ioctl.h>

/* SM-R800 pinned Linux 4.19 dpu30/decon.h. Compat ioctl forwards
 * the native layout unchanged, including 8-byte dma_addr_t alignment. */
#define R800_MAX_DECON_WIN	3
#define R800_WIN_STATE_DISABLED	0
#define R800_WIN_STATE_BUFFER	2
#define R800_FMT_RGBA_8888	2
#define R800_BLENDING_NONE	0

struct r800_win_rect { int x, y; uint32_t w, h; };
struct r800_frame { int x, y; uint32_t w, h, f_w, f_h; };
struct r800_dpp_params {
	uint64_t addr[3];
	int rot, eq_mode, comp_src, hdr_std;
	uint32_t min_luminance, max_luminance;
};
struct r800_win_config {
	int state;
	union {
		uint32_t color;
		struct {
			int fd_idma[3];
			int acq_fence;
			int rel_fence;
			int plane_alpha;
			int blending;
			uint32_t channel;
			int format;
			struct r800_dpp_params dpp_parm;
			struct r800_win_rect block_area;
			struct r800_win_rect transparent_area;
			struct r800_win_rect opaque_area;
			struct r800_frame src;
		};
	};
	struct r800_frame dst;
	_Bool protection;
	_Bool compression;
};
struct r800_win_config_data {
	int retire_fence;
	int fd_odma;
	struct r800_win_config config[R800_MAX_DECON_WIN + 1];
};
#define R800_S3CFB_WIN_CONFIG _IOW('F', 209, struct r800_win_config_data)

_Static_assert(sizeof(struct r800_win_rect) == 16, "DECON rect ABI");
_Static_assert(sizeof(struct r800_frame) == 24, "DECON frame ABI");
_Static_assert(sizeof(struct r800_dpp_params) == 48, "DECON DPP ABI");
_Static_assert(offsetof(struct r800_win_config, fd_idma) == 8, "DECON DMA FD offset");
_Static_assert(offsetof(struct r800_win_config, acq_fence) == 20, "DECON acquire offset");
_Static_assert(offsetof(struct r800_win_config, rel_fence) == 24, "DECON release offset");
_Static_assert(offsetof(struct r800_win_config, format) == 40, "DECON format offset");
_Static_assert(offsetof(struct r800_win_config, dpp_parm) == 48, "DECON DPP offset");
_Static_assert(offsetof(struct r800_win_config, src) == 144, "DECON src offset");
_Static_assert(offsetof(struct r800_win_config, dst) == 168, "DECON dst offset");
_Static_assert(offsetof(struct r800_win_config, protection) == 192, "DECON protection offset");
_Static_assert(offsetof(struct r800_win_config, compression) == 193, "DECON compression offset");
_Static_assert(sizeof(struct r800_win_config) == 200, "DECON window ABI");
_Static_assert(offsetof(struct r800_win_config_data, config) == 8, "DECON config offset");
_Static_assert(sizeof(struct r800_win_config_data) == 808, "DECON ioctl payload ABI");
_Static_assert(R800_S3CFB_WIN_CONFIG == 0x432846d1UL, "DECON ioctl command ABI");
#endif
