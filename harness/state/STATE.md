# STATE — 2026-11-19T11:30:00Z（night-07 修复会话 · 终稿）

## 已完成（R5 全部 4 findings 修复，全部 CI 绿；035/032 附真实回归）

- **F-032 ✅ 5fb3e54 + 实机重放**：credentials 探针的扫描域剔除 `proxy/sources.json`（远程订阅内容落点，从不进 guest；白名单化反而开洗白通道——声明与注释已写明边界）。实机：毒订阅（48-hex password）import 后 escape-test contained rc=0（修复前 ❌ exit 1）。
- **F-035 ✅ 6a2aac8**：spawn_daemon 的 no-record+pid-alive 分支等待一拍（3×400ms：在途守护会发布 record 且 serving→Ok；垂死守护退场）后落到全新 spawn（与 F-028 run_id 交接机制互补）。单测：真 spawn_daemon 等待 ≥1.1s 且不短路。R5 的 r5-race-probe 是修复前判定的复刻，对本修复无效（记档）。
- **F-033 ✅ e9c3b1f**：cmd_setup 成功后写 `state/fingerprint.txt`（VM 被承诺的指纹）——死探针激活；测试覆盖一致→Contained、漂移→Escaped（提示 re-pin）。附带修掉 private.rs 测试临时名的并行碰撞 flake（subsec-nanos 混合计数器）。
- **F-034 ✅ 4e5daa9**：provision node 下载改 tmp+mv 原子落位，失败清理残尸——apt 兜底不再被 /usr/local/bin 的半截尸体遮蔽（断言入测试）。

## 版本

v0.5.1（tag）：night-07 hardening。35/35 findings 全闭环（R1 14 + R2 4 + R3 5 + R4 4 + R5 4 + 夜修自发现 4）。

## 下一步（按序 3 条）

1. **R6 回归审查**（重点：night-07 修复面——sources.json 豁免的反向利用面（把秘密藏进订阅？声明边界）、spawn 等待拍的新竞态、fingerprint 戳与 running record 双源一致性、原子下载的 mv 跨设备边界）+ 0.5 证据链攻击面（evidence.rs 单源信任、trace 伪造、observe 超时与 Checking 窗口）。
2. **0.6 multi-env/snapshots**（RELEASES 顺延后的主题）。
3. 模型驱动逃逸演练 + Devin 介入（用户定时）。

## 关键记忆（≤8 条）

1. 探针扫描域的"豁免"与"白名单"是两个方向：豁免=域外（订阅内容不进 guest，不可操纵预言机）；白名单=入已发集（给远程内容开洗白）。选豁免。
2. 管道会吃 exit code：`cmd | tail && next` 的判断失真——CI 判绿必须存 RC 再分支（本会话险些把红树 commit 进去）。
3. spawn_daemon 的三态去重：record+serving→Ok；record 死→retire+respawn；**无 record+pid 活→等待一拍**（在途 vs 垂死分离），超时 spawn 由 run_id 交接兜底。
4. 独立 rustc 探针（逐字复制判定逻辑）只能复现它复刻时的逻辑——修复后的复验必须走真实函数（单测/真 CLI）。
5. curl -o 的中途残尸是经典坑：下载原子化（tmp+mv）优于 --remove-on-error（依赖 curl 版本）。
6. fingerprint 双源（setup 戳 + running record）语义：戳=VM 承诺快照（探针用），record=运行时锁（up 用）——互补不冲突。

## 会话统计

- night-07：4/4（032/033/034/035），4 commit（5fb3e54→4e5daa9），每 commit 完整 ci.sh RC=0
- 累计 35 findings 全修复；环境无残留
