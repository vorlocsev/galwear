"""Run the actual production restart loop with disposable foreground workers."""
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/"payload/android-helper.sh").read_text()
HELPERS=SOURCE.split("# BEGIN GNSS_CHILD_SUPERVISOR\n",1)[1].split("# END GNSS_CHILD_SUPERVISOR",1)[0]
LOOP=SOURCE.split("# BEGIN GNSS_RESTART_LOOP\n",1)[1].split("# END GNSS_RESTART_LOOP",1)[0]
WORKER="""import pathlib,signal,sys
name=sys.argv[1]
def log(event):
    with open("events","a") as f:
        f.write(event+":"+name+"\\n")
def stop(sig,frame):
    log("TERM")
    sys.exit(0)
signal.signal(signal.SIGTERM,stop)
log("START")
pathlib.Path(name+".ready").touch()
while True:
    signal.pause()
"""
ADAPTERS=r'''
B=env
k() { printf '%s\n' "$*" >> events; }
gnss_launch_lhd() { exec python3 worker.py "lhd-$n"; }
gnss_launch_gpsd() { exec python3 worker.py "gpsd-$n"; }
gnss_launch_bridge() { exec python3 worker.py "bridge-$n"; }
gnss_bridge_available() { return 0; }
gnss_donor_config() { [ "$MODE" != config-fail ]; }
gnss_shared_directory() {
    if [ "$MODE" = ipc-down ] || { [ "$MODE" = ipc-recover ] && [ "$n" -eq 1 ]; }; then
        return 1
    fi
    if [ "$MODE" = ipc-lost ] && [ -n "$gpsd_pid" ]; then return 1; fi
    return 0
}
gnss_prepare_owner() {
    [ "$MODE" != owner-fail ]
}
gnss_observe_socket() { return 0; }
await_worker() {
    count=0
    while [ ! -f "$1-$n.ready" ]; do
        [ "$count" -lt 100 ] || exit 9
        sleep 0.02
        count=$((count+1))
    done
}
gnss_delay() {
    case "$1" in
        20)
            await_worker lhd
            if [ "$MODE" = lhd-fail ]; then
                kill -KILL "$lhd_pid"
                wait "$lhd_pid" 2>/dev/null || :
            fi ;;
        5)
            await_worker gpsd
            if [ "$MODE" = gpsd-fail ]; then
                kill -KILL "$gpsd_pid"
                wait "$gpsd_pid" 2>/dev/null || :
            fi ;;
        3)
            await_worker bridge
            kill -KILL "$bridge_pid"
            wait "$bridge_pid" 2>/dev/null || : ;;
        10)
            [ -z "$lhd_pid$gpsd_pid$bridge_pid" ] || exit 8
            printf 'CLEAN:%s\n' "$n" >> events ;;
        *) exit 7 ;;
    esac
}
'''


class RestartLoopTests(unittest.TestCase):
    def run_mode(self,mode):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"worker.py").write_text(WORKER)
            script='MODE=$1\n'+ADAPTERS+HELPERS+LOOP+'''
trap 'stop_stack' EXIT
gnss_restart_loop 2 || exit $?
[ -z "$lhd_pid$gpsd_pid$bridge_pid" ]
'''
            proc=subprocess.Popen(["sh","-c",script,"fixture",mode],cwd=root,
                                  start_new_session=True,stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,text=True)
            try:
                stdout,stderr=proc.communicate(timeout=35)
                self.assertEqual(proc.returncode,0,stdout+stderr)
                events=(root/"events").read_text().splitlines()
            finally:
                try:
                    os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.communicate(timeout=5)
        self.assertEqual([e for e in events if e.startswith("gnss: stack attempt ")],
                         ["gnss: stack attempt 1","gnss: stack attempt 2"])
        self.assertEqual(events.count("gnss: restart budget exhausted"),1)
        self.assertEqual(events.count("CLEAN:1"),1)
        self.assertLess(events.index("CLEAN:1"),events.index("START:lhd-2"))
        return events

    def test_ipc_unavailable(self):
        events=self.run_mode("ipc-down")
        self.assertEqual([e for e in events if e.startswith("START:")],
                         ["START:lhd-1","START:lhd-2"])

    def test_ipc_recovers(self):
        events=self.run_mode("ipc-recover")
        self.assertEqual([e for e in events if e.startswith("START:")],
                         ["START:lhd-1","START:lhd-2","START:gpsd-2","START:bridge-2"])

    def test_ipc_lost_before_bridge(self):
        events=self.run_mode("ipc-lost")
        self.assertFalse(any(e.startswith("START:bridge") for e in events))

    def test_configuration_failure(self):
        events=self.run_mode("config-fail")
        self.assertFalse(any(e.startswith(("START:gpsd","START:bridge")) for e in events))
        self.assertEqual(events.count("gnss: donor configuration unavailable; no GPS workers"),2)

    def test_ownership_failure(self):
        events=self.run_mode("owner-fail")
        self.assertFalse(any(e.startswith(("START:gpsd","START:bridge")) for e in events))

    def test_lhd_failure(self):
        events=self.run_mode("lhd-fail")
        self.assertFalse(any(e.startswith(("START:gpsd","START:bridge")) for e in events))

    def test_gpsd_failure(self):
        events=self.run_mode("gpsd-fail")
        self.assertFalse(any(e.startswith("START:bridge") for e in events))

    def test_bridge_failure_budget(self):
        events=self.run_mode("bridge-fail")
        self.assertEqual([e for e in events if e.startswith("START:bridge")],
                         ["START:bridge-1","START:bridge-2"])
        self.assertEqual([e for e in events if e.startswith("TERM:")],
                         ["TERM:gpsd-1","TERM:lhd-1","TERM:gpsd-2","TERM:lhd-2"])


if __name__=="__main__":
    unittest.main()
