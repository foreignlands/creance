#!/usr/bin/env python3
"""r30-negative-controls — mutation-verify the v0.6.21 fixes (F-098..F-102) and the sealed-token claim.
Per case: cp backup -> literal replace (must match exactly once) -> needle count before/after proves landing
-> cargo fmt (a committed mutation would be fmt-clean) -> cargo test --workspace -> if green, also
cargo clippy --all-targets -D warnings (CI-equivalent) -> restore from backup; md5 check at the end.
RED = test-RC!=0 with 'panicked'/'FAILED' in the log, or clippy/fmt red. GREEN = whole CI gate passes.
Env: CREANCE_REPO (worktree under $HOME, NOT /tmp — see NC-MP3 note), ONLY="names", NC_LOGS."""
import hashlib, os, shutil, subprocess, sys, tempfile
from cases import CASES
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.environ.get("CREANCE_REPO") or os.path.abspath(os.path.join(HERE, "../../.."))
LOGS = os.environ.get("NC_LOGS") or os.path.join(HERE, "logs")
ONLY = set(os.environ.get("ONLY", "").split())
os.makedirs(LOGS, exist_ok=True)
os.chdir(REPO)
files = sorted({e[0] for c in CASES for e in c["edits"]} | {"crates/creance/src/main.rs"})
md5 = lambda p: hashlib.md5(open(p, "rb").read()).hexdigest()
ref = {f: md5(f) for f in files}
bak = tempfile.mkdtemp(prefix="r30-nc.")
for f in files:
    os.makedirs(os.path.join(bak, os.path.dirname(f)), exist_ok=True); shutil.copy(f, os.path.join(bak, f))
def restore():
    for f in files: shutil.copy(os.path.join(bak, f), f)
def run(cmd, log):
    with open(log, "a") as fh:
        fh.write(f"\n$ {' '.join(cmd)}\n"); fh.flush()
        return subprocess.call(cmd, stdout=fh, stderr=subprocess.STDOUT)
try:
    for c in CASES:
        name = c["name"]
        if ONLY and name not in ONLY: continue
        log = os.path.join(LOGS, name + ".log"); open(log, "w").write(c.get("why", "") + "\n")
        needle = c["needle"]; nf = c["edits"][0][0]
        before = open(nf).read().count(needle)
        ok = True
        for (f, old, new) in c["edits"]:
            t = open(f).read()
            if t.count(old) != 1:
                print(f"{name}: HARNESS-ERROR anchor count={t.count(old)} in {f}"); ok = False; break
            open(f, "w").write(t.replace(old, new))
        if not ok: restore(); continue
        run(["cargo", "fmt", "--all"], log)
        after = open(nf).read().count(needle)
        trc = run(["cargo", "test", "--workspace", "--locked", "-q"], log)
        txt = open(log).read()
        cerr = txt.count("error[E") + txt.count("could not compile")
        fail = txt.count("panicked") + txt.count("FAILED")
        crc = "-"
        if trc == 0:
            crc = run(["cargo", "clippy", "--workspace", "--all-targets", "--locked", "-q", "--", "-D", "warnings"], log)
        verdict = "GREEN" if trc == 0 and crc == 0 else ("HARNESS-ERROR(compile)" if cerr and not fail else "red")
        print(f"{name}: needle before={before} after={after} test-RC={trc} panicked/FAILED={fail} compile-err={cerr} clippy-RC={crc} => {verdict}", flush=True)
        restore()
finally:
    restore()
    bad = [f for f in files if md5(f) != ref[f]]
    print("md5-restore:", "OK" if not bad else f"MISMATCH {bad}", f"({len(files)} files)")
    shutil.rmtree(bak)
