#!/bin/bash
# ere-matrix.sh — R14 收敛轮：F-056 转义表的全元字符引擎矩阵（真二进制驱动）。
# R13.5 只实机测过 +、(、a+b/aab 四场景；本探针把 14 个 POSIX ERE 元字符
# 全部过一遍真 `creance proxy-stop`（reap_orphan_cores），并带交叉匹配
# 守卫（`d.`/`d*`/`d?` vs `dx`、`d+` vs 邻居）——转义若缺失，这些邻居会被
# 误杀。每次批内 ≤5 个假核心并发（协议 ≤10 进程）。
# 平台边界：macOS/BSD regex；Linux glibc 的 `\]` 等转义接受度留 Ubuntu 回填。
set -u
ROOT=/tmp/r14-ere-matrix
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN=${CREANCE_BIN:-$(cd "$HERE/../../.." && pwd)/target/release/creance}
FAKE="$HERE/fakecore.c"

setup_batch() { # $@ = 批内目录 tag
  pkill -f "$ROOT/" 2>/dev/null; sleep 0.3
  rm -rf "$ROOT"; mkdir -p "$ROOT"
  clang -o "$ROOT/mihomo-bin" "$FAKE" || { echo "CLANG_FAIL"; exit 1; }
  for dn in "$@"; do
    d="$ROOT/prof-$dn/proxy"
    mkdir -p "$d" || { echo "MKDIR_FAIL $dn"; exit 1; }
    cp "$ROOT/mihomo-bin" "$d/mihomo"
    printf '{\n  "proxy_url": "socks5://127.0.0.1:17896",\n  "dns_url": "https://1.1.1.1/dns-query",\n  "timezone": "Etc/UTC",\n  "locale": "en_US.UTF-8",\n  "browser_language": "en-US"\n}\n' \
      > "$ROOT/prof-$dn/config.json"
  done
}

spawn() { # $1 = tag；fakecore 自守护化（fork 即退），subshell 同步返回
  d="$ROOT/prof-$1/proxy"
  ( PROBE_PID_FILE="$ROOT/pid-$1" "$d/mihomo" -d "$d" >/dev/null 2>&1 )
}

alive() { # $1 = tag; 0 = alive
  [ -f "$ROOT/pid-$1" ] && ps -o pid= -p "$(cat "$ROOT/pid-$1")" >/dev/null 2>&1
}

run_batch() { # $@ = tags；逐个 stop 并验证：目标死、未停邻居全活
  local batch=("$@")
  for t in "${batch[@]}"; do spawn "$t"; done
  sleep 0.6
  local failed=0
  local stopped=" "
  for t in "${batch[@]}"; do
    CREANCE_CONFIG="$ROOT/prof-$t/config.json" "$BIN" proxy-stop \
      >"$ROOT/stop-$t.log" 2>&1
    local rc=$?
    if alive "$t"; then
      echo "MISS  [$t] 自身孤儿未被收割 (stop rc=$rc)"
      tail -3 "$ROOT/stop-$t.log" | sed 's/^/      /'
      failed=1
    fi
    for other in "${batch[@]}"; do
      [ "$other" = "$t" ] && continue
      case "$stopped" in *" $other "*) continue ;; esac
      if ! alive "$other"; then
        echo "CROSSKILL [$t] 的 stop 误杀了邻居 [$other]"
        tail -3 "$ROOT/stop-$other.log" 2>/dev/null | sed 's/^/      /'
        failed=1
      fi
    done
    stopped="$stopped$t "
  done
  [ "$failed" = 0 ] && echo "BATCH OK: ${batch[*]}"
  return $failed
}

echo "== F-056 escape table engine matrix (real binary, macOS/BSD regex) =="
ok=0
setup_batch 'd\' 'd.' 'dx' 'd*' 'd+' && run_batch 'd\' 'd.' 'dx' 'd*' 'd+' && ok=$((ok+1))
setup_batch 'd[' 'd]' 'd{' 'd}' 'd(' && run_batch 'd[' 'd]' 'd{' 'd}' 'd(' && ok=$((ok+1))
setup_batch 'd)' 'd^' 'd$' 'd|' 'd?' && run_batch 'd)' 'd^' 'd$' 'd|' 'd?' && ok=$((ok+1))
setup_batch 'plain' 'dz' 'd-' 'a+b' 'aab' && run_batch 'plain' 'dz' 'd-' 'a+b' 'aab' && ok=$((ok+1))
pkill -f "$ROOT/" 2>/dev/null; sleep 0.3; rm -rf "$ROOT"
echo "== batches passed: $ok/4 =="
[ "$ok" = 4 ] || exit 1
