#ifndef R800_GPS_EPOCH_FRAME_H
#define R800_GPS_EPOCH_FRAME_H
#include "../tools/gps/gps_frame.h"

/* Tag each read batch with the locally observed session epoch. A partial
 * frame spanning an epoch change must be discarded through its newline.
 * This cannot identify complete stale frames already queued by the peer. */
struct gps_epoch_frame {
    struct gps_frame frame;
    unsigned long epoch;
    int dropping;
};

static inline void gps_epoch_reset(struct gps_epoch_frame *f, unsigned long epoch)
{
    f->frame.used = 0;
    f->epoch = epoch;
    f->dropping = 0;
}

static inline int gps_epoch_byte(struct gps_epoch_frame *f, unsigned long epoch,
                                 unsigned char byte)
{
    if (f->epoch != epoch) {
        if (f->frame.used) f->dropping = 1;
        f->frame.used = 0;
        f->epoch = epoch;
    }
    if (f->dropping) {
        if (!byte) return -1;
        if (byte == '\n') f->dropping = 0;
        return 0;
    }
    return gps_frame_byte(&f->frame, byte);
}
#endif
