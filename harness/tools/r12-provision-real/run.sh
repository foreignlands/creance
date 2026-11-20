#!/bin/sh
# R12 探针驱动：dash 实机执行【真实生成的 provision 文本】（非复刻）。
# 判据：
#   P1 real-exec.sh   → URL 架构段非空（linux-arm64/linux-x64）→ F-055 修复面成立
#   P2 oldbug-exec.sh → URL 架构段为空 → 负控（探针具鉴别力）
#   P3a real-exec 与 byte-exact 差异仅 /etc 路径重写（4 行 = 8 diff 行；
#       rules.v4 与 up.rules 共享一行）
#   P3b 工具链段与 r11 探针 heredoc 等价（允许差异：lima.rs 原文含
#       F-034 两行注释，r11 复刻不含——语义中性）
set -u
REPO=/Users/shenyiyu/Documents/zcode/claude-cage-rs
HERE=$REPO/harness/tools/r12-provision-real
export RUSTUP_HOME=$REPO/.toolchain/rustup CARGO_HOME=$REPO/.toolchain/cargo
PATH=$REPO/.toolchain/cargo/bin:$PATH
export PATH

STAGE=$(mktemp -d /tmp/r12-f055-real.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT
cargo run --release --quiet --manifest-path "$HERE/Cargo.toml" -- "$STAGE" > /dev/null || exit 2

# rootfs 目录树（/etc 重写落点）
for d in etc/profile.d etc/sysctl.d etc/iptables etc/sudoers.d; do
  mkdir -p "$STAGE/rootfs/$d"
done

# stub 集：脚本里所有外部命令；sh → dash（Ubuntu /bin/sh 语义）
FB=$STAGE/fakebin
mkdir -p "$FB"
for t in hostnamectl locale-gen update-locale apt-get timeout curl mv chmod bash sysctl iptables iptables-save passwd getent; do
  printf '#!/bin/sh\nexit 0\n' > "$FB/$t"
done
cat > "$FB/curl" <<'EOF'
#!/bin/sh
echo "CURL: $*" >> "$LOG"
exit 22
EOF
cat > "$FB/apt-get" <<'EOF'
#!/bin/sh
echo "APT: $*" >> "$LOG"
exit 0
EOF
cat > "$FB/timeout" <<'EOF'
#!/bin/sh
shift
"$@"
EOF
cat > "$FB/bash" <<'EOF'
#!/bin/sh
echo "BASH: $*" >> "$LOG"
exit 0
EOF
cat > "$FB/getent" <<'EOF'
#!/bin/sh
exit 2
EOF
cat > "$FB/mv" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$FB/"*
ln -sf /bin/dash "$FB/sh"

run_case() { # $1=script $2=logfile
  LOG=$2
  export LOG
  PATH=$FB:$PATH /bin/dash "$1" > /dev/null 2> "$STAGE/err.log"
  echo "rc=$?"
}

echo "=== P1: real-exec.sh (fixed form)"
run_case "$STAGE/real-exec.sh" "$STAGE/calls-real.log"
URL_R=$(grep '^CURL: .*nodejs.org' "$STAGE/calls-real.log" | head -1)
echo "URL_R: $URL_R"

echo "=== P2: oldbug-exec.sh (old-bug negative control)"
run_case "$STAGE/oldbug-exec.sh" "$STAGE/calls-old.log"
URL_O=$(grep '^CURL: .*nodejs.org' "$STAGE/calls-old.log" | head -1)
echo "URL_O: $URL_O"

RC=0
case "$URL_R" in
  *linux-arm64*|*linux-x64*) echo "P1 PASS: real text URL carries arch segment" ;;
  *) echo "P1 FAIL: $URL_R"; RC=1 ;;
esac
case "$URL_O" in
  *linux-/bin/node*) echo "P2 PASS: negative control reproduces empty arch segment" ;;
  *) echo "P2 FAIL: $URL_O"; RC=1 ;;
esac

echo "=== P3a: byte-exact vs exec diff"
diff "$STAGE/real-byte-exact.sh" "$STAGE/real-exec.sh" > "$STAGE/exe.diff" || true
DIFFC=$(grep -c '^[<>]' "$STAGE/exe.diff")
echo "diff lines: $DIFFC (expect 8: /etc rewrites touch 4 lines, rules.v4+up.rules share one)"
[ "$DIFFC" -eq 8 ] || { echo "P3a FAIL"; RC=1; }
echo "--- diff record:"
cat "$STAGE/exe.diff"

echo "=== P3b: toolchain segment vs r11 probe heredoc"
sed -n "/timeout \"\$TOOLCHAIN_BUDGET\" sh -c/,/^' \|\| true$/p" \
  "$HERE/../r11-regression/f054-provision-quotes.sh" > "$STAGE/segment-probe.txt"
if cmp -s "$STAGE/segment-real.txt" "$STAGE/segment-probe.txt"; then
  echo "P3b PASS: toolchain segment byte-identical to r11 probe"
else
  diff "$STAGE/segment-probe.txt" "$STAGE/segment-real.txt" > "$STAGE/seg.diff" || true
  echo "P3b diff (probe < vs real >):"
  cat "$STAGE/seg.diff"
  NONC=$(grep '^[<>]' "$STAGE/seg.diff" | grep -vc '^[<>] *#')
  if [ "$NONC" -eq 0 ]; then
    echo "P3b PASS-equivalent: only comment-line deltas (F-034 note in real text)"
  else
    echo "P3b FAIL: non-comment divergence"; RC=1
  fi
fi

echo "=== P4: aarch64 branch (fake uname, real-guest semantics)"
printf '#!/bin/sh\necho aarch64\n' > "$FB/uname"
chmod +x "$FB/uname"
run_case "$STAGE/real-exec.sh" "$STAGE/calls-arm.log"
rm -f "$FB/uname"
URL_A=$(grep '^CURL: .*nodejs.org' "$STAGE/calls-arm.log" | head -1)
echo "URL_A: $URL_A"
case "$URL_A" in
  *linux-arm64*) echo "P4 PASS: aarch64 branch yields linux-arm64" ;;
  *) echo "P4 FAIL: $URL_A"; RC=1 ;;
esac

echo "=== final RC"
echo "FINAL_RC=$RC"
exit "$RC"
