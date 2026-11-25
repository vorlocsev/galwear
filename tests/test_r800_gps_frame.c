/* Host-only test of the exact framing implementation used by gpsbridge. */
#include <assert.h>
#include <string.h>
#include "../src/tools/gps/gps_frame.h"

int main(void)
{
    struct gps_frame f = {{0}, 0};
    const char *p = "START\nSTOP\n";
    const char *expected[] = {"START","STOP"};
    unsigned int lines = 0;
    for (; *p; p++) {
        int r = gps_frame_byte(&f, (unsigned char)*p);
        assert(r >= 0);
        if (r == 1) {
            assert(lines < 2);
            assert(strcmp(f.line, expected[lines++]) == 0);
            f.used = 0;
        }
    }
    assert(lines == 2);
    assert(gps_frame_byte(&f, 'T') == 0);
    assert(gps_frame_byte(&f, 0) == -1);
    f.used = 0;
    for (unsigned int i = 0; i < 510; i++)
        assert(gps_frame_byte(&f, 'x') == 0);
    assert(gps_frame_byte(&f, '\n') == 1);
    assert(strlen(f.line) == 510);
    f.used = 0;
    for (unsigned int i = 0; i < 510; i++)
        assert(gps_frame_byte(&f, 'x') == 0);
    assert(gps_frame_byte(&f, 'S') == -1);
    f.used = 0;
    assert(gps_frame_byte(&f, '\n') == 1);
    assert(strcmp(f.line,"") == 0);
    return 0;
}
