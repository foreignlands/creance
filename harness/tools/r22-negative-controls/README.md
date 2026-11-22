r22-negative-controls — mutation tests for the v0.6.13 (F-078..081) fixes plus F-076 regressions; `sh run.sh` (CREANCE_REPO overrides the repo root). Evidence: evidence.log.
Column note: `compile-err` counts `^error` lines, which includes cargo's `error: test failed` trailer — a red case shows 1 there without any compile error; `failed`/test-RC are the verdict.
