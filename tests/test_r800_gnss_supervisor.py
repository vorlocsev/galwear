"""Run actual child-supervisor shell helpers against disposable processes."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/"payload/android-helper.sh").read_text()
HELPERS=SOURCE.split("# BEGIN GNSS_CHILD_SUPERVISOR\n",1)[1].split("# END GNSS_CHILD_SUPERVISOR",1)[0]


class SupervisorTests(unittest.TestCase):
    def run_case(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            # Only disposable processes in this isolated shell; EXIT cleanup
            # uses its own child PIDs, not any supplied or external process.
            script='set -eu\nB=env\nk() { printf "%s\\n" "$*"; }\n'+HELPERS+"""
cleanup() {
    for pid in "$bridge_pid" "$gpsd_pid" "$lhd_pid"; do
        [ -n "$pid" ] || continue
        kill -KILL "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
    done
}
trap cleanup EXIT
"""+body
            result=subprocess.run(["sh","-c",script],cwd=tmp,capture_output=True,
                                  text=True,timeout=25)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_live_child(self):
        self.run_case("""
sleep 60 & lhd_pid=$!
lhd_start=$(child_identity "$lhd_pid")
child_alive "$lhd_pid" "$lhd_start"
stop_child "$lhd_pid" "$lhd_start"
if kill -0 "$lhd_pid" 2>/dev/null; then exit 1; fi
lhd_pid=
""")

    def test_wrong_starttime_no_signal(self):
        self.run_case("""
sleep 60 & lhd_pid=$!
lhd_start=$(child_identity "$lhd_pid")
if child_alive "$lhd_pid" "$((lhd_start+1))"; then exit 1; fi
if stop_child "$lhd_pid" "$((lhd_start+1))"; then exit 1; fi
child_alive "$lhd_pid" "$lhd_start"
""")

    def test_unknown_starttime_no_signal(self):
        self.run_case("""
sleep 60 & lhd_pid=$!
lhd_start=$(child_identity "$lhd_pid")
if stop_child "$lhd_pid" ""; then exit 1; fi
child_alive "$lhd_pid" "$lhd_start"
""")

    def test_exited_child(self):
        self.run_case("""
sleep 60 & gpsd_pid=$!
gpsd_start=$(child_identity "$gpsd_pid")
kill -TERM "$gpsd_pid"
wait "$gpsd_pid" 2>/dev/null || :
if child_alive "$gpsd_pid" "$gpsd_start"; then exit 1; fi
stop_child "$gpsd_pid" "$gpsd_start"
gpsd_pid=
""")

    def test_stop_stack(self):
        self.run_case("""
sleep 60 & lhd_pid=$!; lhd_start=$(child_identity "$lhd_pid")
sleep 60 & gpsd_pid=$!; gpsd_start=$(child_identity "$gpsd_pid")
sleep 60 & bridge_pid=$!; bridge_start=$(child_identity "$bridge_pid")
lp=$lhd_pid; gp=$gpsd_pid; bp=$bridge_pid
stop_stack
[ -z "$lhd_pid$gpsd_pid$bridge_pid$lhd_start$gpsd_start$bridge_start" ]
if kill -0 "$lp" 2>/dev/null; then exit 1; fi
if kill -0 "$gp" 2>/dev/null; then exit 1; fi
if kill -0 "$bp" 2>/dev/null; then exit 1; fi
""")

    def test_uncertain_child_blocks_stack_restart(self):
        self.run_case("""
sleep 60 & lhd_pid=$!; lhd_start=$(child_identity "$lhd_pid")
sleep 60 & bridge_pid=$!; bridge_start=$(child_identity "$bridge_pid")
bridge_start=$((bridge_start+1))
if stop_stack; then exit 1; fi
[ -z "$lhd_pid" ]
[ -n "$bridge_pid" ]
kill -0 "$bridge_pid"
""")

    def test_supervisor_not_its_own_child(self):
        self.run_case('if child_identity "$supervisor_pid"; then exit 1; fi\n')

    def test_invalid_pid(self):
        self.run_case('for pid in 0 -1 bogus; do if child_identity "$pid"; then exit 1; fi; done\n')


if __name__=="__main__":
    unittest.main()
