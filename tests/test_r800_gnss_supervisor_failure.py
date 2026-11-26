"""Real disposable worker failure/restart tests using the production shell helpers."""
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/"payload/android-helper.sh").read_text()
HELPERS=SOURCE.split("# BEGIN GNSS_CHILD_SUPERVISOR\n",1)[1].split("# END GNSS_CHILD_SUPERVISOR",1)[0]
TRAPS=SOURCE.split("# END GNSS_CHILD_SUPERVISOR\n",1)[1].split("        # Existing kernel-owned GPIO",1)[0]
WORKER="""import os, pathlib, signal, sys
name=sys.argv[1]
def record(event):
    with open("events","a") as f:
        f.write(event+":"+name+"\\n")
def stop(sig, frame):
    record("TERM")
    sys.exit(0)
if name.endswith("-ignore"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
else:
    signal.signal(signal.SIGTERM, stop)
record("START")
pathlib.Path(name+".ready").touch()
while True:
    signal.pause()
"""
HARNESS=r'''
set -eu
B=env
k() { printf "%s\n" "$*"; }
'''
START=r'''
start_stack() {
    python3 worker.py "lhd-$1" & lhd_pid=$!
    lhd_start=$(child_identity "$lhd_pid")
    python3 worker.py "gpsd-$1" & gpsd_pid=$!
    gpsd_start=$(child_identity "$gpsd_pid")
    python3 worker.py "bridge-$1" & bridge_pid=$!
    bridge_start=$(child_identity "$bridge_pid")
    count=0
    while [ ! -f "lhd-$1.ready" ] || [ ! -f "gpsd-$1.ready" ] || [ ! -f "bridge-$1.ready" ]; do
        [ "$count" -lt 100 ] || exit 3
        sleep 0.05
        count=$((count+1))
    done
    child_alive "$lhd_pid" "$lhd_start"
    child_alive "$gpsd_pid" "$gpsd_start"
    child_alive "$bridge_pid" "$bridge_start"
}
assert_gone() {
    for pid in "$@"; do
        if kill -0 "$pid" 2>/dev/null || [ -e "/proc/$pid" ]; then exit 4; fi
    done
}
'''


class FailureTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        (self.root/"worker.py").write_text(WORKER)

    def events(self):
        return (self.root/"events").read_text().splitlines()

    def launch(self,body):
        proc=subprocess.Popen(["sh","-c",HARNESS+HELPERS+TRAPS+START+body],
                              cwd=self.root,start_new_session=True,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.addCleanup(self.cleanup,proc)
        return proc

    def cleanup(self,proc):
        # Only this fixture's private process group, including descendants.
        try:
            os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate(timeout=5)

    def finish(self,proc):
        stdout,stderr=proc.communicate(timeout=30)
        self.assertEqual(proc.returncode,0,stdout+stderr)

    def crash(self,role):
        body=r'''
start_stack first
lp=$lhd_pid; gp=$gpsd_pid; bp=$bridge_pid
kill -KILL "$TARGET"
wait "$TARGET" 2>/dev/null || :
if child_alive "$TARGET" "$STAMP"; then exit 5; fi
stop_stack
assert_gone "$lp" "$gp" "$bp"
printf 'OLD_GONE\n' >> events
start_stack second
lp=$lhd_pid; gp=$gpsd_pid; bp=$bridge_pid
stop_stack
assert_gone "$lp" "$gp" "$bp"
'''
        body=body.replace("$TARGET","$"+role+"_pid").replace("$STAMP","$"+role+"_start")
        self.finish(self.launch(body))
        events=self.events()
        boundary=events.index("OLD_GONE")
        self.assertEqual([e for e in events[:boundary] if e.startswith("TERM:")],
                         ["TERM:"+n+"-first" for n in ("bridge","gpsd","lhd") if n!=role])
        self.assertEqual(sorted(e for e in events[:boundary] if e.startswith("START:")),
                         sorted("START:"+n+"-first" for n in ("bridge","gpsd","lhd")))
        self.assertEqual(sorted(e for e in events[boundary+1:] if e.startswith("START:")),
                         sorted("START:"+n+"-second" for n in ("bridge","gpsd","lhd")))
        self.assertEqual([e for e in events[boundary+1:] if e.startswith("TERM:")],
                         ["TERM:"+n+"-second" for n in ("bridge","gpsd","lhd")])

    def test_lhd_crash(self):
        self.crash("lhd")
    def test_gpsd_crash(self):
        self.crash("gpsd")
    def test_bridge_crash(self):
        self.crash("bridge")

    def test_term_ignoring_child(self):
        proc=self.launch(r'''
python3 worker.py bridge-ignore & bridge_pid=$!
bridge_start=$(child_identity "$bridge_pid")
count=0
while [ ! -f bridge-ignore.ready ]; do
    [ "$count" -lt 100 ] || exit 3
    sleep 0.05
    count=$((count+1))
done
bp=$bridge_pid
stop_stack
assert_gone "$bp"
''')
        self.finish(proc)
        self.assertEqual(self.events(),["START:bridge-ignore"])

    def test_supervisor_term(self):
        proc=self.launch(r'''
start_stack first
printf '%s %s %s\n' "$lhd_pid" "$gpsd_pid" "$bridge_pid" > pids.tmp
mv pids.tmp ready
while :; do sleep 0.1; done
''')
        deadline=time.monotonic()+10
        while not (self.root/"ready").is_file() and time.monotonic()<deadline:
            self.assertIsNone(proc.poll())
            time.sleep(0.05)
        pids=[int(x) for x in (self.root/"ready").read_text().split()]
        proc.send_signal(signal.SIGTERM)
        self.finish(proc)
        self.assertEqual([e for e in self.events() if e.startswith("TERM:")],
                         ["TERM:bridge-first","TERM:gpsd-first","TERM:lhd-first"])
        for pid in pids:
            self.assertFalse(Path(f"/proc/{pid}").exists())


if __name__=="__main__":
    unittest.main()
