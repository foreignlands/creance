#!/bin/sh
# F-052 修复面 CLI 侧四 case（R11 回归）：cmd_up 的 stamp 三分支 + 实例存在检查。
# 用 target/release/creance 实机驱动（无需 lima/VM——三分支都在 limactl 之前）。
#
# 运行：sh f052-up-branches.sh  （仓库根；需 target/release/creance 存在）
# 期望：case1/2/3 全部 rc=1 且文案含恢复指引；case4 rc=0 且 limactl 恰好被
#       调用一次 `start <instance>`（模板陷阱关闭——不克隆 default）。
set -u
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
BIN="$REPO/target/release/creance"
[ -x "$BIN" ] || { echo "no $BIN — 先跑 sh scripts/ci.sh"; exit 2; }

FP='5e2a08008a823a41bae7f4dd2721ecd2224ea76e8f2101b302d1f74001ad246a' # ["Etc/UTC","en_US.UTF-8","en-US"] sha256（r11-regression h2.1 锚）
TD=$(mktemp -d /tmp/r11-f052-probe.XXXXXX)
trap 'rm -rf "$TD"' EXIT
mkdir -p "$TD/profile/state"
export CREANCE_CONFIG="$TD/profile/config.json"
"$BIN" init >/dev/null || { echo "init 失败"; exit 2; }
INSTANCE=$("$BIN" --help >/dev/null 2>&1; echo) # 占位，真实名在 case4 由文案抓取

fails=0
say() { printf '%s\n' "$*"; }

# case1 老 profile 升级路径：无戳 up → 拒 + 指引
out=$("$BIN" up 2>&1); rc=$?
case "$out" in
  *"fingerprint 戳缺失或不可读"*"creance setup"*) c1=PASS ;;
  *) c1="FAIL ←←←（out=$out）"; fails=$((fails+1)) ;;
esac
[ "$rc" = 1 ] || { c1="FAIL(rc=$rc) ←←←"; fails=$((fails+1)); }
say "case1 无戳（0.5.5 前老 profile 直接 up）  预测=rc1+戳缺失文案    实际=$c1"

# case2 漂移戳 → 拒
echo deadbeef > "$TD/profile/state/fingerprint.txt"
out=$("$BIN" up 2>&1); rc=$?
case "$out" in
  *"guest 环境（时区/语言）自创建以来已变更"*) c2=PASS ;;
  *) c2="FAIL ←←←（out=$out）"; fails=$((fails+1)) ;;
esac
[ "$rc" = 1 ] || { c2="FAIL(rc=$rc) ←←←"; fails=$((fails+1)); }
say "case2 漂移戳                             预测=rc1+漂移文案      实际=$c2"

# case3 戳对 + 实例缺失 → 拒（模板陷阱）
echo "$FP" > "$TD/profile/state/fingerprint.txt"
out=$("$BIN" up 2>&1); rc=$?
INSTANCE=$(printf '%s' "$out" | sed -n 's/.*实例 \([^ ]*\) 不存在.*/\1/p')
case "$out" in
  *"不存在（未 setup 或已被删除）"*"creance setup"*) c3=PASS ;;
  *) c3="FAIL ←←←（out=$out）"; fails=$((fails+1)) ;;
esac
[ "$rc" = 1 ] || { c3="FAIL(rc=$rc) ←←←"; fails=$((fails+1)); }
say "case3 戳对+实例缺失                      预测=rc1+实例缺失文案  实际=$c3 (instance=$INSTANCE)"

# case4 戳对 + 实例在（假 lima home）+ 假 limactl → 绿路径恰一次 start
UID_=$(id -u)
H=$(printf '%s' "$TD/profile" | shasum -a 256 | cut -c1-8)
LH="/tmp/cage-lima-${UID_}-${H}"
mkdir -p "$LH/$INSTANCE"
touch "$LH/$INSTANCE/lima.yaml"
mkdir -p "$TD/fakebin"
cat > "$TD/fakebin/limactl" <<EOF
#!/bin/sh
echo "limactl \$*" >> "$TD/calls.log"
exit 0
EOF
chmod +x "$TD/fakebin/limactl"
rm -f "$TD/calls.log"
out=$(PATH="$TD/fakebin:$PATH" "$BIN" up 2>&1); rc=$?
calls=$(cat "$TD/calls.log" 2>/dev/null)
if [ "$rc" = 0 ] && [ "$calls" = "limactl start $INSTANCE" ]; then c4=PASS; else
  c4="FAIL ←←←（rc=$rc calls=[$calls]）"; fails=$((fails+1));
fi
say "case4 全对（假 limactl）                  预测=rc0+恰一次 start 实际=$c4"

rm -rf "$LH"
[ "$fails" = 0 ] && say "=== f052-up-branches: 4/4 PASS ===" || say "=== f052-up-branches: $fails FAIL ==="
exit $fails
