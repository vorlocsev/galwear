"""Host-only checks of actual GNSS parsing helpers and source guards."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GnssRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/gps_r800.c").read_text()
        cls.bridge = (ROOT / "src/tools/gps/gpsbridge.c").read_text()
        s = cls.source
        helpers = s[s.index("static int number("):s.index("static void handle_line(")]
        harness = r'''
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    size_t size; uint16_t flags;
    double latitude, longitude, altitude;
    float speed, bearing, accuracy;
    int64_t timestamp;
} GpsLocation;
''' + helpers + r'''
int main(int argc,char **argv) {
    if (argc != 3) return 2;
    GpsLocation loc;
    if (!strcmp(argv[1],"fix")) return parse_fix(argv[2],&loc) ? 0 : 1;
    if (!strcmp(argv[1],"nmea")) return valid_nmea(argv[2]) ? 0 : 1;
    return 2;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "fixture.c"
        cls.exe = Path(cls.tmp.name) / "fixture"
        src.write_text(harness)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def check_case(self, kind, value, expected):
        r = subprocess.run([str(self.exe), kind, value], timeout=5)
        self.assertEqual(r.returncode, expected, value)

    def test_valid_fix(self):
        self.check_case("fix", " 31 52.1 4.3 10 0 180 5 1700000000000", 0)

    def test_invalid_coordinates_and_numbers(self):
        for value in (
            " 31 91 4 0 0 0 5 1",
            " 31 52 181 0 0 0 5 1",
            " 31 nan 4 0 0 0 5 1",
            " 31 52 4 inf 0 0 5 1",
            " 31 52 4 0 -1 0 5 1",
            " 31 52 4 0 0 360 5 1",
            " 31 52 4 0 0 0 -5 1",
            " 32 52 4 0 0 0 5 1",
            " 2 52 4 0 0 0 5 1",
            " 31 52 4 0 0 0 5 9223372036854775808",
            " 31 52 4 0 0 0 5 1 extra",
            " 31 52 4 0 0 0 5 0",
        ):
            self.check_case("fix", value, 1)

    def test_valid_nmea_checksum(self):
        self.check_case("nmea", "$GPGLL,4916.45,N,12311.12,W,225444,A,*1D", 0)

    def test_invalid_nmea_checksum(self):
        for value in ("", "$ABC", "$ABC*00", "$ABC*4Z", "$ABC*40x", "$A\t*00"):
            self.check_case("nmea", value, 1)

    def test_hal_reader_owns_close(self):
        s = self.source
        send = s[s.index("static int send_line("):s.index("static void report_status(")]
        self.assertIn("MSG_NOSIGNAL | MSG_DONTWAIT", send)
        self.assertIn("shutdown(sock, SHUT_RDWR)", send)
        self.assertNotIn("close(sock);", send)

    def test_bridge_reader_owns_close(self):
        s = self.bridge
        out = s[s.index("static void out("):s.index("static int daemon_mode")]
        self.assertIn("shutdown(client, 2)", out)
        self.assertNotIn("close(client);", out)

    def test_failed_session_not_marked_active(self):
        self.assertIn("if (session(1))", self.bridge)
        self.assertIn("if (session(0))", self.bridge)

    def test_overlong_frame_not_reinterpreted(self):
        self.assertIn("if (!ch || have == sizeof(buf) - 1)", self.source)
        self.assertIn("if (!discard)", self.source)


if __name__ == "__main__":
    unittest.main()
