#!/bin/sh
# A1 runner：
#   1) 库层探针（serde_yaml 0.9.34，8 MiB / 2 MiB 栈）
#   2) 黑盒集成（release/creance proxy import --file，主线程 8 MiB = 生产 CLI 路径）
# payload 放 mktemp 临时目录，跑完即删。
set -u
cd "$(dirname "$0")"
ROOT=${CREANCE_REPO:-$(cd ../../.. && pwd)}
if [ -d "$ROOT/.toolchain/cargo/bin" ]; then
  export RUSTUP_HOME=$ROOT/.toolchain/rustup CARGO_HOME=$ROOT/.toolchain/cargo PATH=$ROOT/.toolchain/cargo/bin:$PATH
fi
cargo build --release --quiet 2>&1 | head -3
BIN=target/release/a1-yaml-bomb

echo "== 1) 库层探针 =="
for v in deep-seq-1k deep-seq-10k deep-seq-100k deep-map-10k alias-bomb alias-undefined alias-self alias-fwd tag-binary-huge; do
  for s in 8 2; do
    out=$(perl -e 'alarm 60; exec @ARGV' -- "$BIN" "$v" "$s" 2>&1); rc=$?
    case $rc in
      0) echo "[OK ] $v stack=${s}MiB :: $out";;
      101|134|139) echo "[CRASH rc=$rc] $v stack=${s}MiB :: $(echo "$out" | tail -3 | tr '\n' ' ')";;
      *) echo "[?? rc=$rc] $v stack=${s}MiB :: $(echo "$out" | tail -3 | tr '\n' ' ')";;
    esac
  done
done

echo "== 2) 黑盒集成：creance proxy import --file =="
CREANCE=$ROOT/target/release/creance
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
TMPDIR_A1="$TMP" python3 - <<'EOF'
import os
tmp = os.environ["TMPDIR_A1"]
def w(name, text):
    with open(os.path.join(tmp, name), "w") as f:
        f.write(text)

w("deep1e4.yaml", "proxies: " + "["*10000 + "]"*10000 + "\n")
w("deep1e5.yaml", "proxies: " + "["*100000 + "]"*100000 + "\n")
lines = ["a0: &a0 [1,2,3,4,5,6,7,8,9,10]"]
for lvl in range(1, 10):
    lines.append("a%d: [%s]" % (lvl, ", ".join(["*a%d" % (lvl-1)]*10)))
lines.append("proxies: [*a9, *a9]")
w("bomb.yaml", "\n".join(lines) + "\n")
w("undef.yaml", "proxies:\n  - *ghost\n")
node = "  - name: n{0}\n    type: ss\n    server: 1.2.3.4\n    port: 1\n    cipher: aes-128-gcm\n    password: x\n"
w("n3000.yaml", "proxies:\n" + "".join(node.format(i) for i in range(3000)))
w("n3001.yaml", "proxies:\n" + "".join(node.format(i) for i in range(3001)))
EOF
for f in deep1e4 deep1e5 bomb undef n3000 n3001; do
  out=$( ( cd "$TMP" && CREANCE_CONFIG="$TMP/config.json" perl -e 'alarm 60; exec @ARGV' -- "$CREANCE" proxy-import --name "$f" --file "$TMP/$f.yaml" 2>&1; echo "rc=$?" ) )
  echo "--- $f :: $(echo "$out" | tr '\n' ' ' | cut -c1-400)"
done
