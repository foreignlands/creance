#!/bin/bash
# probe.sh — F-056 三方向复现驱动。
# 用法: bash probe.sh <scenario>   scenario ∈ {setupA,setupB,setupC,setupD,stopA,stopB,stopC,stopD,checkA,checkB,checkC,checkD,clean}
# 每个场景分两步：setupX（编译假核心+脱离父进程派生，ppid==1）与 stopX
# （跑真 creance proxy-stop），checkX 观察假核心是否存活。
# 设计要点：spawn 与 creance 分开跑，避免驱动 shell 自身 cmdline 含签名文本。
set -u
ROOT=/tmp/r13-ere
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN=/Users/shenyiyu/Documents/zcode/claude-cage-rs/target/release/creance
FAKE="$HERE/fakecore.c"

setup() { # $1=场景名 $2=目录名
  local sc="$1" dn="$2"
  local d="$ROOT/$dn/proxy"
  rm -rf "$ROOT/$dn"
  mkdir -p "$d"
  clang -o "$d/mihomo" "$FAKE" 2>"$ROOT/clang.log" || { echo "CLANG_FAIL"; exit 1; }
  # 双 fork：子 shell 立即退出 → 假核心被 launchd 收养（ppid==1）
  ( PROBE_PID_FILE="$ROOT/$sc.pid" "$d/mihomo" -d "$d" -f "$d/config.yaml" >/dev/null 2>&1 & )
  sleep 0.5
  local pid
  pid=$(cat "$ROOT/$sc.pid" 2>/dev/null)
  echo "SCENARIO=$sc DIR=$d PID=$pid PPID=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')"
}

stoprun() { # $1=场景名 $2=目录名
  local sc="$1" dn="$2"
  CREANCE_CONFIG="$ROOT/$dn/config.json" "$BIN" proxy-stop >"$ROOT/$sc.stoplog" 2>&1
  echo "STOP_RC=$?"
}

check() { # $1=场景名 $2=目录名
  local sc="$1" dn="$2"
  local d="$ROOT/$dn/proxy" pid
  pid=$(cat "$ROOT/$sc.pid" 2>/dev/null)
  if ps -o pid= -p "$pid" >/dev/null 2>&1; then
    echo "ALIVE pid=$pid ppid=$(ps -o ppid= -p "$pid" | tr -d ' ')"
  else
    echo "DEAD pid=$pid"
  fi
}

clean() {
  # 兜底杀掉所有残存的假核心，再删临时树
  pkill -f "$ROOT/" 2>/dev/null
  sleep 0.3
  rm -rf "$ROOT"
  echo CLEANED
}

case "${1:-}" in
  setupA) setup A plain ;;
  setupB) setup B 'a+b' ;;
  setupC) setup C aab ;;
  setupD) setup D 'paren(1' ;;
  stopA) stoprun A plain ;;
  stopB) stoprun B 'a+b' ;;
  stopC) stoprun C aab ;;   # 注意：C 用 B 的 profile 触发（跨目录误杀面）
  stopCv) CREANCE_CONFIG="$ROOT/aab/config.json" "$BIN" proxy-stop >"$ROOT/Cv.stoplog" 2>&1; echo "STOP_RC=$?" ;;
  stopD) stoprun D 'paren(1' ;;
  checkA) check A plain ;;
  checkB) check B 'a+b' ;;
  checkC) check C aab ;;
  checkD) check D 'paren(1' ;;
  clean) clean ;;
  *) echo "usage: $0 <scenario>"; exit 2 ;;
esac
