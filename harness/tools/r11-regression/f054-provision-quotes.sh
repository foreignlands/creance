#!/bin/sh
# F-055 探针（R11 发现）：provision 工具链段的 `'"$ARCH"'` 在【外层】shell 展开，
# 而 ARCH 只在【内层】sh -c 脚本里赋值 —— 展开时恒为空，URL 变成
# node-v22.14.0-linux-/bin/node（所有架构 404），curl -f 失败 → 恒走 apt 兜底。
# night-12 ca22ea2 的 commit message 声称 "the download URL is even right on
# arm64" —— 本探针证明该声称不成立（dash 逐字复刻 lima.rs 生成的引号结构）。
#
# 运行：sh f054-provision-quotes.sh
# 期望（修复后）：URL 含 linux-arm64（本机 uname -m 为 arm64 时）；
# 现状（v0.5.6）：URL 是 linux-（空架构）→ FAIL = 洞在。
set -u
TD=$(mktemp -d /tmp/r11-f054-probe.XXXXXX)
trap 'rm -rf "$TD"' EXIT
mkdir -p "$TD/fakebin"
for t in curl apt-get timeout bash mv chmod rm uname; do
  : # uname 用真的；其余 stub
done
cat > "$TD/fakebin/curl" <<'EOF'
#!/bin/sh
echo "CURL: $*" >> "$LOG"
exit 22
EOF
cat > "$TD/fakebin/apt-get" <<'EOF'
#!/bin/sh
echo "APT: $*" >> "$LOG"
exit 0
EOF
cat > "$TD/fakebin/timeout" <<'EOF'
#!/bin/sh
shift
"$@"
EOF
cat > "$TD/fakebin/bash" <<'EOF'
#!/bin/sh
echo "BASH: $*" >> "$LOG"
exit 0
EOF
cat > "$TD/fakebin/mv" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$TD/fakebin/"*
LOG="$TD/calls.log"
export LOG
cat > "$TD/outer.sh" <<'OUTER'
#!/bin/sh
set -e
TOOLCHAIN_BUDGET=300
APT_OPTS="-o Acquire::http::Timeout=20 -o Acquire::Retries=1"
timeout "$TOOLCHAIN_BUDGET" sh -c '
  apt-get update -qq || true
  apt-get install '"$APT_OPTS"' -y -qq curl git ca-certificates xz-utils >/dev/null || true
  ARCH=$(case "$(uname -m)" in aarch64) echo arm64;; *) echo x64;; esac)
  if curl -fsSL -m 120 https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-$ARCH/bin/node -o /usr/local/bin/node.new 2>/dev/null && mv /usr/local/bin/node.new /usr/local/bin/node 2>/dev/null; then
    chmod +x /usr/local/bin/node 2>/dev/null || true
  else
    rm -f /usr/local/bin/node.new
    apt-get install '"$APT_OPTS"' -y -qq nodejs npm >/dev/null || true
  fi
  curl -fsSL -m 120 https://claude.ai/install.sh | bash >/dev/null 2>&1 || true
' || true
OUTER
# 内层 sh 用 dash（Ubuntu guest 的 /bin/sh 语义）
ln -sf /bin/dash "$TD/fakebin/sh"
PATH="$TD/fakebin:$PATH" /bin/dash "$TD/outer.sh"
echo "--- 记录的调用："
cat "$LOG"
URL=$(grep '^CURL: .*nodejs.org' "$LOG" | head -1)
case "$URL" in
  *linux-arm64*|*linux-x64*)
    echo "PASS: URL 含架构段（F-055 已修复）"; exit 0 ;;
  *linux-*)
    echo "FAIL ←←← URL 架构段为空（F-055 洞在）：$URL"
    exit 1 ;;
  *)
    echo "UNKNOWN: $URL"; exit 2 ;;
esac
