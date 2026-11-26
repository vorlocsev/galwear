#include <assert.h>
#include <stdio.h>
#include "../src/tools/gps/gps_callback_gate.h"

int main(void)
{
    assert(!gps_callback_allowed(GPS_CALLBACK_CLOSED, 0));
    assert(!gps_callback_allowed(GPS_CALLBACK_CLOSED, 1));
    assert(gps_callback_allowed(GPS_CALLBACK_ACTIVE, 0));
    assert(gps_callback_allowed(GPS_CALLBACK_ACTIVE, 1));
    assert(!gps_callback_allowed(GPS_CALLBACK_STOPPING, 0));
    assert(gps_callback_allowed(GPS_CALLBACK_STOPPING, 1));
    assert(!gps_callback_allowed((enum gps_callback_phase)99, 0));
    assert(!gps_callback_allowed((enum gps_callback_phase)99, 1));
    puts("GPS_CALLBACK_GATE=PASS");
    return 0;
}
