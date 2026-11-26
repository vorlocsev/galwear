#ifndef R800_GPS_CALLBACK_GATE_H
#define R800_GPS_CALLBACK_GATE_H

/* All accesses are serialized by the caller's callback mutex.
 * Never hold that mutex while invoking a vendor slot. */
enum gps_callback_phase {
    GPS_CALLBACK_CLOSED, GPS_CALLBACK_ACTIVE, GPS_CALLBACK_STOPPING
};

static inline int gps_callback_allowed(enum gps_callback_phase phase, int status)
{
    return phase == GPS_CALLBACK_ACTIVE ||
           (phase == GPS_CALLBACK_STOPPING && status);
}

#endif
