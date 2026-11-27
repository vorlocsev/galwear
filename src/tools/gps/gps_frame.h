/* Bounded newline framing for GPS bridge. No libc or target ABI dependency. */
#ifndef R800_GPS_FRAME_H
#define R800_GPS_FRAME_H
#define GPS_FRAME_CAPACITY 512
struct gps_frame {
    char line[GPS_FRAME_CAPACITY];
    unsigned int used;
};

/* Return 1 for a complete line, 0 for pending input, -1 for invalid input.
 * Caller disconnects on -1, and resets used after dispatching a complete line.
 * A maximum of 510 payload bytes leaves room for a newline and terminator. */
static int gps_frame_byte(struct gps_frame *frame, unsigned char byte)
{
    if (byte == 0 || frame->used >= GPS_FRAME_CAPACITY - 1)
        return -1;
    if (byte == '\n') {
        frame->line[frame->used] = 0;
        return 1;
    }
    if (frame->used >= GPS_FRAME_CAPACITY - 2)
        return -1;
    frame->line[frame->used++] = (char)byte;
    return 0;
}
#endif
