# r23-negative-controls

Mutation matrix for F-082..084 fixes (v0.6.14) plus F-076/078/079/081 regressions. cp backup, perl inject, grep -c landing proof, cargo test --locked, restore, md5sum -c.

    sh harness/tools/r23-negative-controls/run.sh > evidence.log   # per-case cargo output in logs/

test-RC!=0 = guarded; test-RC=0 = no guard (see F-087). Note: the `compile-err` column counts `^error` lines, which includes cargo's `error: test failed` summary, not only compile errors.
