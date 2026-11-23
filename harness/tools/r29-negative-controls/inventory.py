#!/usr/bin/env python3
"""Run the remaining ci.sh leg (scripts/check-probe-inventory.sh) on every GREEN case; restore + md5 check."""
import hashlib, os, shutil, subprocess
from cases import CASES
REPO = os.environ["CREANCE_REPO"]; ONLY = set(os.environ["ONLY"].split()); os.chdir(REPO)
md5 = lambda p: hashlib.md5(open(p, "rb").read()).hexdigest()
for c in CASES:
    if c["name"] not in ONLY: continue
    fs = sorted({e[0] for e in c["edits"]}); keep = {f: open(f).read() for f in fs}; ref = {f: md5(f) for f in fs}
    for f, o, n in c["edits"]:
        t = open(f).read(); assert t.count(o) == 1; open(f, "w").write(t.replace(o, n))
    rc = subprocess.call(["sh", "scripts/check-probe-inventory.sh"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    for f in fs: open(f, "w").write(keep[f])
    print(f"{c['name']}: probe-inventory RC={rc} restore={'OK' if all(md5(f)==ref[f] for f in fs) else 'MISMATCH'}")
