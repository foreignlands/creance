# FINDING-061: 基础镜像供应链信任根弱于 fetch-proxy-core——SHA256SUMS 同通道取回、GPG 签名未验证，注释却自称 signed-by-construction

- **编号**: 061
- **严重度**: S4（信任模型弱点 + 注释过度宣称；利用前置 = TLS/CA 层攻破 cloud-images.ubuntu.com 通道）
- **攻击面**: H7
- **发现时间**: 2026-11-21T13:30:00Z
- **发现者会话**: r13
- **状态**: 待修复

## 复现（必须）

```sh
# 证据 1：校验和与镜像同通道取回，签名文件根本没碰
grep -n "SHA256SUMS" crates/creance-vm/src/qemu/image.rs   # :53 只 fetch SHA256SUMS，无 .gpg、无 gpg 验签
# 证据 2：注释宣称
sed -n '50,51p' crates/creance-vm/src/qemu/image.rs
#   "Verify against the release's signed-by-construction checksum file"
#   ——cloud-images.ubuntu.com 的 SHA256SUMS 有配套 SHA256SUMS.gpg（Ubuntu 签名键），
#     代码既不拉取也不验签："signed-by-construction" 名不符实
# 证据 3：对照同仓库更强先例
sed -n '8,12p' scripts/fetch-proxy-core.sh   # 钉版哈希录在仓库=第二通道
```

- **期望**: 600MB 可执行根盘的信任根不应与被验对象同通道；注释应如实。
- **实际**: MITM/CA 妥协者同时给 img + 量身 SHA256SUMS 即通过（parse_sum 只
  查行格式与名字精确匹配，校验和本身取自攻击者）。对照：fetch-proxy-core 的
  钉版哈希（F-056 之外本轮已验证其四项全清）有仓库 git 历史作第二通道。

## 根因猜测

image.rs:50-51 把"HTTPS 同域"当成了签名（"signed-by-construction"）；GPG 验签
需要内嵌/分发 Ubuntu 签名键，可能被认为超出 dev-script 范畴——但 Roadmap 已把
该镜像定为可执行根盘，信任根应与 fetch-proxy-core 对齐。

## 未验证想法

- 下载后的缓存镜像永不复验（trust-on-first-verify）：base_image_path 存在后
  `ensure_base_image` 直接返回（image.rs:38-39），无 stored-hash 复验——同 uid
  篡改缓存镜像 = 注入 guest 根盘（自伤面记档，与 H3 seed 改写同族）。
- parse_sum 遇单字段行 early-return None → 整体拒绝（fail-closed ✓），但同通道
  攻击者可追加坏行做下载 DoS——无害。

## 建议修复方向（供第二天的人参考，非结论）

拉取 SHA256SUMS.gpg 并用内嵌 Ubuntu cloud-image 签名键验签（gpgv + 二进制键
或 fetch 首次 pin 键指纹入仓库）；同时给缓存镜像落 stored-hash 复验；修注释。
