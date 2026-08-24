# 项目进度日志

> 记录已完成工作的产物、验证状态和遗留问题。计划文档见 `plan_b_cose.md` 和 `plan_a_icse.md`。

## 2026-07-19

### 1. 已完成并在权威远端验证：RQ2 fresh-CVE typing stability 双 pass、strict merge 与 evaluator

本次完成：

- 通过 `ssh-vuln-adj` 进入权威环境 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`，并核对 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`
- 重新探测 OpenAI-compatible primary：最小 `pong` 成功，但正式单行结构化请求仍返回 HTTP 402。runner 原本已有未暴露的 `max_output_tokens` 调用逻辑，本次补充 CLI 参数，并将 output-token cap 写入 seal、请求日志、逐行 provenance 与 merge fail-closed 校验；即使绑定 `512`，正式单行仍返回 402，说明当前配额不足以承担完整请求
- 远端 `xje` Codex CLI provider 随后恢复。废弃并归档 OpenAI 请求状态后，以 `codex-cli 0.144.4`、二进制 SHA-256、`gpt-5.5`、medium reasoning、read-only sandbox、ephemeral session 重新 seal；样本、worklist、prompt 和六列预测保持不变
- 完成 A/B 两个逆序 reviewer pass，各 `1,250/1,250` 行。A 使用 28 个 ephemeral sessions，B 使用 67 个，A/B session ID 集合零交集；所有行保持 `label_is_human=false`
- B 有 3 个批次因 affected_versions 缺少允许的显式 `version_reasoning_type` 被 strict validator 整批拒绝，涉及首个报错样本 `:967`、`:179`、`:073`；拒绝批次未写入 reviewer JSONL，随后从断点重新调用并通过。当前 runner 未将这类 validation exception 写成 `response_error`，因此 B 日志表现为 `70 request / 67 response_success / 0 response_error`，这是已记录的 provenance 缺口
- strict merge 与 evaluator 均完成；六个 profile 在本 cohort 上逐行相同，production default 未改变

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/reviewer_a.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/reviewer_b.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/manifest.sealed.json`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/dual_review_consensus.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/dual_review_summary.json`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/typing_holdout_evaluation.json`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/evaluation_manifest.json`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/failed_openai_unbounded_output_v1_20260719/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/failed_openai_capped_output_v1_20260719/`

验证：

- reviewer A/B 均为 `1,250` 行、`1,250` 个唯一 sample ID；A/B reviewer SHA-256 分别为 `871dcaeb0b1c1fadf886adb94a8b5b1f72efaa18c15dfae5850076b4988c9b48`、`f28aad01257f6a931a732c02a75cccad8c94e8c4345d810edba9c55f00324b34`
- strict merge 逐行验证 schema、prompt/input/manifest hash、backend version/hash、reasoning、session、usage、`schedule=input` 和 session-disjoint contract；merge manifest SHA-256 为 `b51c7960263182cdcf9901a6d6d3714c8e6c982f585fba5e2a8b0fb3927fd0b7`
- A/B exact label agreement 为 `1,167/1,250`（`0.9336`），Cohen's kappa 为 `0.9091`；strict consensus 为 `1,147/1,250`（coverage `0.9176`）
- current baseline 在 strict 子集上命中 `931/1,147`，accuracy `0.8117`、macro-F1 `0.8293`；full-cohort lower-bound accuracy 为 `0.7448`，corpus-reweighted strict accuracy 为 `0.8125`
- CVE-cluster bootstrap `2,000` 次：strict accuracy 95% interval `[0.7894, 0.8351]`，full-cohort lower-bound 95% interval `[0.7200, 0.7688]`
- 每字段 strict coverage / strict accuracy：affected_versions `0.7680 / 0.7552`，cwe_ids `0.9160 / 0.9913`，published `1.0000 / 1.0000`，references `0.9480 / 0.9916`，severity `0.9560 / 0.3096`
- evaluator 重跑返回 0，`typing_holdout_evaluation.json` SHA-256 前后均为 `4652e64667b21e6b1231ae61587a34570922ca6b72a0671afb55387b78829d6b`
- 权威远端四个核心 Python 文件通过 `py_compile`；runner tests `9/9`、RQ2 全目录 tests `66/66`
- 已更新 COSE setup/results/discussion/threats/conclusion 并重建 `paper/cose/full_draft.md`，原始 `wc -w=14,375`；package validator 的 silver/affected_versions claim-boundary lints 均通过
- package validator 仍为 `status=fail`、`submission_ready=false`：投稿 blocker 仍包括 RQ2/RQ3 现实人工签收为 0 和投稿元数据占位；rerender 另受 ImageMagick `convert` 缺失、既有 latexmk error state 及 LaTeX fatal/emergency-stop log 阻塞

当前效果：

- 当前快照上可以报告 non-human typing stability、双 pass agreement、strict coverage、selective accuracy、full-cohort lower bound、设计重加权结果和 CVE-cluster bootstrap
- severity 是最明确的薄弱字段：239 条 strict 行只有 74 条与 baseline 一致，即 165 条 disagreement；affected_versions 次之。该观察用于现实人工复核排序，不证明 Codex consensus 就是真值
- published、references 和 cwe_ids 的高一致只说明该当前样本与同模型 strict consensus 的一致性，不能外推为 human-gold accuracy
- 六个 profile 的预测完全相同，因此 candidate comparison 仍不可识别；本轮没有 references/CWE candidate gain，也没有 production switch

未验证：

- A/B 是相同模型、相同 prompt/config 下由 28/67 个 ephemeral sessions 组成的两个顺序 pass，不是两位现实人类，也不是独立模型家族
- 全项目现实 human signoff 仍为 0；这些结果不具备 human-gold claim 资格
- 3 个被拒绝批次的原始 JSON 未由 runner 保存，无法审计其 substantive label 是否与后续通过输出不同
- 当前 cohort 排除了所有已知 candidate-impact CVE，不能验证 references/CWE candidate gain；需要 profile seal 后的新时间 cohort

下一步：

- 从 severity 的 165 条 strict disagreement 和 affected_versions 的 47 条 strict disagreement 开始现实人工复核，保留 annotator、独立 reviewer 和 author signoff 门禁
- 为未来运行修复 validation exception 的 raw-output/error logging，并在新的 seal 中绑定 runner hash；不得事后改写本轮已完成 reviewer 输出
- 单独预注册 profile seal 后的新 NVD-GHSA 时间 cohort，用于 current 与 references/CWE candidates 的可识别比较

### 2. 已完成并在权威远端验证：RQ2 failure-mode 复核与全量现实人工签署包

本次完成：

- 在权威环境 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj` 中核对 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`，逐行连接 1,250 条冻结 source rows 与 dual-review consensus，复核 strict disagreement 的字段、转移和原始值模式
- 新增只读 post-hoc failure-mode diagnostic；该脚本不修改 `scripts/build_field_discrepancies.py`，并在结果中显式记录 `post_hoc=true`、`production_baseline_changed=false`、`valid_for_confirmatory_performance_claim=false`
- 新增全量 1,250 行盲化现实人工包、author-only 调度文件与 fail-closed validator。人工包省略 baseline status/note、sampling stratum、A/B reviewer 与 consensus 字段；两位现实人类必须使用不同 ID 独立判断，作者再签署最终标签

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_rq2_typing_holdout_failure_modes.py`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/typing_holdout_failure_mode_diagnostic.json`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/typing_holdout_failure_mode_cases.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/human_review/rq2_typing_holdout_human_review.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/human_review/author_review_scheduler.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/validate_rq2_typing_human_review.py`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/human_review/rq2_typing_human_review_readiness.json`

验证：

- failure-mode cohort 仍为 `1,250` 行、`1,250` 个唯一 CVE、每字段 `250` 行；strict consensus `1,147` 行，baseline disagreement `216` 行
- severity 的 `165` 条 strict disagreement 均来自 canonical label 相同但 richer review contract 不同：`115` 条 exact vector + one missing score、`17` 条 vector strict-prefix + one missing score、`32` 条不同 vector + one missing score、`1` 条 vector 缺失 + one missing score。当前 baseline 只比较 canonical label，而冻结 reviewer protocol 同时比较 label、score、vector 和 CVSS version，二者构念不一致
- affected_versions 的 `25` 条 EQ→INC disagreement 均为一边原始值为空、另一边仅含 `introduced=0` 且无上界的 package-specific affected claim；`normalize_affected_spans` 将这种记录投影为空，因此 baseline 退化为“两边都空”
- post-hoc diagnostic 在同一 non-human strict 集上由 `931/1,147` 拟合到 `1,121/1,147`，增加 `190` 条命中；其中 severity `+165`、affected_versions `+25`。该数值是同集 failure-mode fit，不是新 holdout、人工准确率或方法提升
- 新增测试在权威远端为 `7/7` failure-mode tests 与 `11/11` human-review validator tests；RQ2 目录全量测试为 `84/84`，核心新文件通过 `py_compile`
- 现实人工包为 `1,250 pending / 0 signed`，每字段 `250` 行，普通来源/盲化校验无错误；author-only 调度为 tier 1 reviewer disagreement `103`、tier 2 baseline-vs-consensus disagreement `216`、tier 3 full completion `931`。`--require-signed` 与 `--require-complete` 均在零签署状态以退出码 `2` 拒绝，builder 重跑也拒绝覆盖现有包
- 已更新 COSE setup/results/discussion/threats/conclusion/submission readiness 并在权威远端重建 `paper/cose/full_draft.md`，原始 `wc -w=14,826`；silver/affected_versions claim-boundary lints 通过

当前效果：

- 已将“severity baseline 低一致”拆成可验证的 protocol construct mismatch，而不是笼统归因于 baseline 错误或 Codex 正确
- 已确认 affected_versions 的 25 条具体 projection loss，可作为后续规则修复候选；当前未修改生产 baseline，以避免在同一揭封 cohort 上调参后宣称提升
- 已为所有五字段提供统一的现实人工 annotator→独立 reviewer→author signoff 路径，不再只对 severity/affected_versions 分歧子集做选择性人工准备

未验证：

- 现实人工签署仍为 `0`；validator 只能校验 ID 不同和文件合同，无法证明某个 ID 对应真实人类，身份与独立性仍需线下核验
- post-hoc diagnostic 完全依赖同一批 same-model consensus，不能替代新时间 cohort 或 human-gold
- affected_versions projection 修复尚未进入生产 comparator，也尚未在新的冻结 cohort 上验证副作用

下一步：

- 两位现实人类从盲化包独立复核，作者可按调度先处理 103 条 reviewer disagreement 和 216 条 baseline disagreement，但最终需完成全部 1,250 行以避免选择性评估
- 全部行通过 `--require-complete` 且线下身份核验后，另行生成 canonical human-gold；当前 packet 本身始终保持 `label_is_human=false`
- 若要改 severity contract 或 affected_versions projection，先固定候选规则，再在 profile seal 之后的新时间 cohort 上做确认性比较

### 3. 已完成并在权威远端验证：RQ2 跨协议 contract-stability no-go

本次完成：

- 将 fresh holdout 的 post-hoc contract projection 回放到旧 RQ2 AI-gold primary `300` 行及 same-model review `60` 行；severity 使用旧 seed 中原本提供给 labeler 的结构化 score/vector context，未补充外部证据
- 对 affected_versions 单独审计输入投影合同：旧 seed 中存在 raw range 已被擦除、仅保留单边 package identity 的行，因此不把当前快照重建的 raw value 当作旧 labeler 当时看到的事实，也不计算伪造的跨 cohort accuracy
- 新增跨协议 advancement gate；只有 severity 方向不反转、affected 输入可比较且已有现实人工签署合同才允许 advance。当前三个条件均不满足，状态为 `no_go_protocol_incompatible`

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_rq2_typing_contract_stability.py`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_stability/rq2_typing_contract_stability.json`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_stability/rq2_typing_contract_stability.md`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_stability/rq2_typing_contract_stability_cases.jsonl`

验证：

- severity 新合同投影在旧 AI-gold primary 为 `32/60`，旧 baseline 为 `55/60`，delta `-23`；在旧 same-model review 为 `5/12` 对 `12/12`，delta `-7`
- 同一投影在 fresh non-human strict severity 上为 `239/239`，旧 baseline 为 `74/239`，delta `+165`。方向在协议代际之间反转，不能合并成一个方法性能数字
- 旧 affected_versions primary 的 `60` 行中有 `10` 行同时满足：两边投影值均为空、仅 GHSA 保留 package identity、baseline 与 non-human label 均为 `equivalent`；fresh strict 中则有 `25` 条保留 raw one-sided unbounded claim 并被标为 `incomplete`
- cases artifact 共 `237` 行；所有结果保持 `label_is_human=false`、`post_hoc=true`、`production_baseline_changed=false`、`pooled_performance_claim_allowed=false`
- 新增 contract-stability tests `6/6`；权威远端 RQ2 目录全量 tests 更新为 `90/90`
- contract-stability JSON/JSONL 重跑 SHA-256 稳定，分别为 `327cd32c04822878ae7243967434bb45b98986a9f17f209aae4a1ef3173aefa9`、`4b91fd839fb4e1a75b72465252b00dca4024f849af92c1900e246de1b6d84877`
- 已更新 COSE setup/results/discussion/threats/conclusion/submission readiness 并重建 `paper/cose/full_draft.md`，原始 `wc -w=15,201`；silver/affected_versions claim-boundary lints 通过

当前效果：

- severity 的 `+165` 被进一步限定为新 prompt 明确缺分规则后的协议内一致性，不再作为候选 comparator 的可推广增益
- affected_versions 的 25 条 fresh projection loss 仍是真实输入机制，但旧 AI-gold 标签没有看到相同 raw claim，不能拿旧/新 accuracy 判断规则优劣
- production baseline 继续保持不变；在共享构念未由现实人类确认前，不冻结新的 candidate time cohort

未验证：

- 尚无共享 calibration rows 被两位现实人类按同一显式 severity/affected contract 签署
- 旧 affected raw snapshot 未在 seed manifest 中按行保留，无法恢复 label-time 输入；当前 aligned snapshot 不能冒充历史输入
- no-go 结论能拒绝当前候选，但不能告诉我们应最终选择“缺 score=equivalent”还是“缺 score=incomplete”

下一步：

- 从全量人工包中先抽取一组覆盖 exact vector/missing score、different vector/same label、unbounded affected presence 的共享 calibration rows；两位现实人类独立标注并由作者固定字段合同
- 按固定合同回标旧/新 cohort 的可比子集；只有方向一致后，才 seal 新候选并收集新的 NVD-GHSA 时间 cohort
- 在此之前，论文只报告 protocol construct drift、input-projection sensitivity 和 no-go gate，不报告 `1,121/1,147` 为方法提升

### 4. 已完成并在权威远端验证：RQ2 AI contract calibration v1/v2 与细粒度 no-go

本次完成：

- 在权威环境 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj` 上核对 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj` 后构建 `contract_calibration_v1`：从 fresh typing cohort 确定性抽取 `60` 行，覆盖四类 severity 边界、单边无界 affected claim 及两组 unchanged controls；A/B 使用完全相同 raw values、同一 prompt、相反顺序和互斥 Codex sessions
- v1 在 reviewer 运行前固定 exact/strict/stratum gate。A/B exact 为 `57/60`、kappa `0.9023`、strict 为 `57/60`；但 affected unchanged control 只有 `6/9` strict expected，故 gate 为 `no_go_ai_calibration_unstable`
- v1 failure analysis 将四个失败分别定位为跨 CVSS 版本不可逐项比较、artifact identity 未建立、prerelease boundary semantics、singleton-versus-interval subset；旧 non-human consensus 在新 strict rows 上复现 `56/57`
- 在 v1 揭封后先写入 refined prompt 与 v2 gate，再构建与 v1 `60` 行完全不重叠的 `contract_calibration_v2` 共 `42` 行。v2 将 same-version/cross-version severity、equal normalized range/package mismatch、singleton-versus-interval、prerelease boundary 及两个 repeat controls 分开
- v2 A/B exact 为 `42/42`、kappa `1.0`、strict 为 `41/42`。四个固定条款全部通过：same-version different vector `8/8` factual conflict、cross-version vector `6/6` representation discrepancy、exact/prefix vector + one missing score `5/5` incomplete、one-sided unbounded affected `5/5` incomplete
- v2 的 equal normalized range/package mismatch 为 `8/8` strict representation discrepancy；singleton-versus-interval 为 `7/7` strict（6 incomplete、1 factual conflict）。prerelease 三行的两位 reviewer 也逐行完全一致，但一行因 broad XWiki CPE 与具体 Maven component identity 未由冻结输入证明而共同标为 `uncertain` 并请求额外复核，故 strict coverage `2/3`，低于预注册 `0.8` 门槛，完整 gate 保持 `no_go_ai_contract_v2_unstable`

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/contract_calibration_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_calibration_v1/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_calibration_v2/`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_typing_contract_calibration_v2.md`

验证：

- v1/v2 reviewer 输出均逐行绑定 prompt/input/manifest、Codex CLI version/hash、model、reasoning、session 和 usage；A/B session 集合互斥，所有结果保持 `label_is_human=false`
- v1 manifest/summary/cases/failure-analysis SHA-256 分别为 `6e71c57909dc6903596ec13f7f2d2e0ed7246fe6235a6e92bc6a623ba8e60df5`、`65a0999b25ee0c41474a5bed581cebe329aa3f78ecab250bdba709dd895fcf0f`、`604d076d25dd29a798715c2328b7b4fdd4e6b560b5f44d4460a02d050269a873`、`aa48e10aed1201bcc9efd5bb40002e3aaee3c84136ff436c2aabc56d422d261b`
- v2 manifest/summary/cases SHA-256 分别为 `a71df80e8927ac2fd7a44073721f004bd5e60c452daeaae3a927b13aa337ff03`、`f1a32ca10af2a6230c0fe02feef38b875ff2448dd5c8ef3aa28c817a2a360d39`、`b459ad2d524a3d16a86ccff238a0d84ef6c8337b120fc6a0c0eb0bd685a3c4f1`
- 新增聚焦测试 `17/17`；权威远端 RQ2 全目录更新为 `107/107`
- 已更新 COSE setup/results/discussion/threats/conclusion/submission readiness 并在权威远端重建 `paper/cose/full_draft.md`，原始 `wc -w=15,797`；claim-boundary lints 通过。package 仍仅受既有 ImageMagick `convert` 缺失和 LaTeX fatal/emergency-stop state 阻塞

当前效果：

- 可以把 severity 合同细化为非人工候选：同 CVSS 版本内 base-vector 冲突与跨 CVSS 版本表示差异必须分开；缺 score 规则在两个 disjoint calibration 中稳定
- 单边无界 affected claim 的 incomplete 规则也跨 v1/v2 稳定；但 affected_versions 仍不能形成完整规则，因为 artifact identity 与 prerelease ordering 需要额外证据
- v2 cross-version 六行相对旧 non-human consensus 全部改变标签，说明显式 prompt 可以稳定控制构念，但这不是六条“纠错”或准确率提升证据
- production comparator 未修改，新时间 cohort 未启动，human-gold 与 confirmatory claim 均仍被 gate 禁止

未验证与下一步：

- v1/v2 都是同模型家族的 development calibration，并从既有 fresh cohort/strict consensus 选行；高一致性不能证明标签是真值
- 现实人工签署仍为 `0`。XWiki artifact-identity 证据已在下述 section 5 补充，但二次 A/B 未收敛；当前需先固定 product/component 集合语义与 prerelease 映射，再由现实人工签署共享 calibration 和全量包
- 只有 full construct gate 与现实人工门禁都通过后，才能冻结生产候选并采集新的 NVD-GHSA 时间 cohort

### 5. 已完成并在权威远端验证：XWiki 单行冻结证据二次审计

本次完成：

- 针对 v2 唯一非 strict 行 `rq2_typing_holdout_v1:148`（`CVE-2023-29206`）构建单行 evidence-backed secondary packet；没有改写 v2 原结果
- 从官方结构化接口冻结 GHSA advisory、修复 commit 及 `XWIKI-19514`、`XWIKI-19583`、`XWIKI-9119` 三条 Jira issue，共 `5` 条 evidence records、`10` 个 response/metadata cache 文件；全部响应和盲表均由 manifest 哈希绑定
- RQ2 runner 仅在输入显式提供时加入冻结 `evidence_context`；允许引用的 URL 仍限制在原盲表已有的 NVD/GHSA references，输出继续强制 `label_is_human=false`
- 使用同一封存输入和 prompt 启动两个互斥 ephemeral Codex sessions。两位 reviewer 均通过至少两条冻结官方 URL 的引用门禁，但 A 给 `uncertain`/medium/review，B 给 `incomplete`/high/no-review，exact `0/1`、strict `0/1`
- A/B 都认可 GHSA、commit 和 Jira 将漏洞定位到 `Skin - Skinx` 组件；分歧集中在 broad product CPE 与 component package 的集合语义，以及 NVD 明列 prerelease 子集能否直接视为 GHSA Maven range 的严格子集
- evidence-augmented gate 为 `no_go_ai_contract_v2_evidence_secondary_unresolved`；v2 仍为 strict `41/42`，prerelease strict coverage 仍为 `2/3`，不冻结生产候选、不启动新时间 cohort

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/evidence_secondary_v1/`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/typing_contract_evidence_secondary_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_calibration_v2/evidence_secondary_v1/`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_typing_contract_evidence_secondary.md`

验证：

- 权威环境复核为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`，运行时核对为 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`
- manifest、reviewer A、reviewer B、cases、summary、merge manifest SHA-256 依次为 `eea80ca36176f7bd21d1a2580703485639f542b823cc9adc33bccd27138ba5d8`、`fac95f15d0eac7e168ba4fac5a47bd23d6f34aa33dd52522ef8b1af4636be696`、`e9bf5a02921c44f699427ca484b48e506d84c1592b7d996706bbb21869c01b0d`、`7ecf4725e55e61da723f12a946a760054ab6ab81ea30b10a1c24fef3c716a34a`、`c74241b1dc1f8ab239addb79f0bacd582bc7bc59c0c60117a304ee549ced748f`、`3b291e18b4a52d4dd68db5b9d89a0dfbe79a7979ae9b5ffe142382ff0b0e00f8`
- A/B session ID 分别为 `019f7712-83da-7280-96f4-4d7ecd325f6e` 与 `019f7713-2cd7-7e02-a80f-d11a0682ef84`，无交集；两者输入 token 均为 `17,786`
- 新增 runner/builder/merger 聚焦测试共 `14/14` 通过；权威远端 RQ2 全目录 `111/111`、runner `10/10` 通过；合并器逐项验证 seal、输入、prompt、backend、session、证据引用与 non-human 边界
- 已同步 setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`，原始 `wc -w=16,043`；package validator 的 claim-boundary checks 通过，仍仅受既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop 阻塞

未验证与下一步：

- 官方证据支持组件归属和 `14.9-rc-1` 修复边界，但没有自动给出“产品 CPE 声明”和“组件包声明”在联合 artifact-version 空间中的偏序；不能把 B 的 `incomplete` 当成新真值，也不能把 A 的拒判当成最终人工结论
- 下一步不再重复 prompt-only AI review；先固定 product-to-component claim 的集合语义、CPE prerelease update 到 Maven qualifier 的映射规则，再由两位现实人类在共享 calibration 中独立裁决并由作者签收

### 6. 已完成并在权威远端验证：XWiki artifact-version lineage 投影诊断

本次完成：

- 在单行 evidence secondary 仍分歧后，新增 fail-closed 的 artifact-version projection audit；该诊断不调用 reviewer、不改写 v2/secondary 标签，只检查 product CPE 与 component package 是否具备进入同一 release domain 的证据条件
- 冻结 XWiki Platform fix-commit README、XWiki Maven repository metadata、`3.1-milestone-1`/`14.8`/`14.9-rc-1` 当前 Skinx POM、两个 XWiki 3.0 tag 的当前模块路径探针，以及旧 `xwiki-plugin-skinx-1.13.1` POM，共 `8` 个官方响应、`16` 个 response/metadata cache 文件
- 组件归属、XWiki 顶层项目同版本发布策略、当前 lineage POM/version 对齐、`14.8` 与 `14.9-rc-1` 上界存在四项通过
- 三项关键检查失败：GHSA 起点 `3.0-milestone-1` 不在当前 `org.xwiki.platform:xwiki-platform-skin-skinx` 的 `585` 条发布目录中；NVD 明列的 `3.0`、`3.0-milestone-2`、`3.0-milestone-3`、`3.0-rc-1` 也均不在；冻结 POM 未提供旧 `com.xpn.xwiki.platform.plugins:xwiki-plugin-skinx:1.13.1` 到当前坐标的显式 lineage mapping
- 当前 Maven 坐标的首条发布为 `3.1-milestone-1`；对 `xwiki-web-3.0-milestone-1` 和 `xwiki-web-3.0` 的当前模块路径探针均为 HTTP `404`。这不能证明 Skinx 功能当时不存在，但反证了把 3.0 product release 直接当作当前 Maven coordinate release 的做法
- 投影 gate 为 `abstain_artifact_version_projection_unresolved`，typing disposition 为 `uncertain`。因此 reviewer B 的 `incomplete` 不能在现有证据合同下升级为候选真值

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_xwiki_artifact_version_projection.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_xwiki_artifact_version_projection.py`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/xwiki_artifact_version_projection_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_calibration_v2/artifact_version_projection_v1/`

验证：

- 独立 verifier 重新验证 input/cache/output SHA-256、当前 catalog 首版本、GHSA/NVD 版本 membership、两个 404 path probes、legacy coordinate 和三个 failed checks，返回 `0`
- analysis、Markdown、manifest SHA-256 分别为 `245cc47ffee265e2fff278a52dc99a8c862144379651289d49fba89c78602a2b`、`ff5db731f08561e8498fc9dd84e39ca76621f296fc11f055ad0a63671ef2af93`、`2386750114126dc7f0e59e0365f9d366944fab9cc5c01008d0a07fcc5da8f9de`
- 新增 analyzer `4/4` 与 verifier `3/3` 聚焦测试；所有输出保持 `label_is_human=false`、`eligible_for_human_gold_claim=false`
- 权威远端 RQ2 全目录测试更新为 `118/118`；论文相关章节已同步并重建 `paper/cose/full_draft.md`，原始 `wc -w=16,241`
- package validator 的 claim-boundary checks 继续通过；`submission_ready=false` 仍仅由既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop 阻塞

当前效果与下一步：

- 当前最保守、可验证的单行结论是 `uncertain`：不是因为组件归属仍未知，而是因为 affected range 跨越了两个不同坐标和版本体系，缺少旧 lineage 到当前 lineage 的显式映射
- 下一步需要冻结 XWiki 3.0 产品构建到旧 Skinx artifact/version 的依赖关系，以及旧/new Skinx 的迁移映射；只有映射完整后才运行 release-set containment。该映射仍须由现实人类在共享 calibration 中确认，不能由本诊断自行生成 human gold

### 7. 已完成并在权威远端验证：XWiki lineage-aware release graph v2

本次完成：

- 继续追踪 v1 projection audit 的三个 failed checks，从 XWiki 自有 Maven/Nexus 冻结五个 XWiki Enterprise 3.0 parent POM、五个 enterprise-web POM、旧 Skinx `1.20/1.21/1.22` POM，以及旧/new lineage 的五个漏洞相关源码文件，共 `33` 个官方证据响应、`66` 个 cache 文件
- product-build dependency edge 已完整落盘：`3.0-milestone-1 → xwiki-plugin-skinx 1.20`、`3.0-milestone-2 → 1.21`、`3.0-milestone-3/rc-1/final → 1.22`；五个 enterprise-web POM 均通过 `${platform.plugin.skinx.version}` 依赖旧坐标
- 旧 `xwiki-plugin-skinx:1.22` 到当前 `xwiki-platform-skin-skinx:3.1-milestone-1` 的迁移连续性通过五个漏洞相关源码文件验证：`AbstractDocumentSkinExtensionPlugin.java`、`JsExtension.java`、`CssExtension.java`、`JsxAction.java`、`SsxAction.java` 在迁移边两侧 `5/5` SHA-256 相同；这些类在旧 `1.20/1.21/1.22` 和当前 `3.1-milestone-1` 均存在
- 将五个 XWiki 3.0 产品版本与当前 Maven catalog 合并为 evidence-bound product release domain，共 `588` 个 release tokens；按显式 milestone < rc < final ordering 投影后，NVD set 为 `412` 条、GHSA set 为 `413` 条，关系为 `strict_subset`
- 唯一 GHSA-only release 为 `3.0-milestone-1`，NVD-only 为空；所有六个 projection v2 checks 通过，gate 为 `artifact_version_projection_allowed_development_only`，development typing candidate 为 `incomplete`
- 该结果明确标为 `post_unsealing_conditional_analysis=true`、`label_is_human=false`、`eligible_for_human_gold_claim=false`；不回写 sealed v2 reviewer result，不把 evidence-secondary A/B 分歧改成 strict consensus，也不允许 production switch

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_xwiki_artifact_version_projection_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_xwiki_artifact_version_projection_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/xwiki_artifact_version_projection_v2/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_calibration_v2/artifact_version_projection_v2/`
- 首次 full-tree fetch 因单响应超过 `2 MB` 被 fail-closed 拒绝，缓存保留在 `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/xwiki_artifact_version_projection_v2_failed_full_tree_20260719/`；正式 v2 改用五个最小相关源码响应

验证：

- 独立 verifier 重新验证 `66` 个 cache files、所有 input/output hashes、五条 product dependency edges、旧/current 坐标、`5/5` source continuity、set cardinality、唯一 GHSA-only release、gate 和 non-human boundary，返回 `0`
- analysis、Markdown、manifest SHA-256 分别为 `278b4c666eb9577037cc88fdd2d8edf5e94f9116fd615f55940c103618f62c96`、`a61b5cacc2bdcf5791311dff775bc91d874d385cde859f70391024c68e62f44d`、`26c727c9309e381e6e87ca41fcfb5ea9969e86029e4e9c1ce8162d09a7f632d9`
- projection v2 analyzer `5/5`、verifier `4/4`；权威远端 RQ2 全目录更新为 `127/127`
- 论文相关章节已同步并在权威远端重建 `paper/cose/full_draft.md`，原始 `wc -w=16,336`；package validator 共运行 `107` 项检查，新增内容未触发 silver/human-gold claim-boundary lint，`submission_ready=false` 仍由现实人工签收、投稿元数据及既有 ImageMagick/LaTeX 构建问题阻塞

当前效果与下一步：

- 对 `CVE-2023-29206`，我的 evidence-bound 技术判断由 v1 的 `uncertain` 更新为 post-unsealing non-human `incomplete` candidate；更新依据是新增 product dependency 和 source migration evidence，不是重复 prompt 或主观改票
- 该单例证明 product/component 比较需要 lineage-aware release graph，也提供了一个可执行模板；但单例 post-hoc 成功不能证明方法泛化。下一步应在不复用此案例规则的其他 artifact-mismatch rows 上做开发覆盖诊断，并由现实人类在共享 calibration 中确认字段合同

### 8. 已完成并在权威远端验证：通用 artifact-lineage 跨案例诊断 v1

本次完成：

- 在抓取跨案例证据前固定 `affected_versions` 通用 graph contract，定义 source subject、product/artifact release、canonical interval、release domain 五类节点，`package_identity`、`product_contains_artifact`、`artifact_alias` 等证据边，以及六项 fail-closed projection gate；任何 identity、boundary、lineage、ordering 或 domain 缺口均返回 `uncertain`
- 新增原始结构 selector：仅从已揭封 v2 source rows 中选择双边非空、每边单一 subject、完整标识不同且非空 raw interval signature 完全相同的行；selector 不读取 reviewer 文件或 consensus label，稳定得到 `8` 条。上游 v2 source 本身仍按非人工 consensus 条件化，已在 manifest 中显式记录
- 八条覆盖 Solr、Sulu、ZITADEL、Mattermost、Moby、Joomla、Craft CMS、Elasticsearch，以及 Maven、Packagist、Go 三个生态；冻结 `33` 个官方 boundary POM、根 `composer.json`、`go.mod` 或 Moby project/registry 响应，共 `66` 个 response/metadata cache 文件
- 八条分别通过 `package_identity`、`product_contains_artifact`、`artifact_alias` 三类边的 `claim_subjects_bound`、`boundary_releases_bound`、`lineage_path_complete`、`ordering_supported`、`shared_release_domain_bound`、`set_relation_computed` 六项 gate；全部 symbolic interval relation 为 `equal`，得到 `8/8` non-human `representation_discrepancy` development candidates，并与封存 A/B 标签 `8/8` 一致

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/affected_versions_lineage_graph_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_artifact_lineage_development_cohort.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_artifact_lineage_cross_case.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_artifact_lineage_cross_case.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/artifact_lineage_cross_case_v1/`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/artifact_lineage_cross_case_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_calibration_v2/artifact_lineage_cross_case_v1/`

验证：

- 独立 verifier 重新核对 cohort seal、contract/code/reviewer input hashes、固定 evidence inventory、全部 `66` 个 cache file hashes 与 URL/status/body hash，并确定性重算 8 条 case analysis、Markdown、summary 和 epistemic boundary，返回 `0`
- cohort、cohort manifest、analysis、Markdown、analysis manifest SHA-256 分别为 `106ff9b716b6a62f284b0fbabbe747b7bd4323d0dc4c94d15ca1c4b140b9e5c1`、`51df862928e06dd7fe771e673b1f7172cad0c0e73bc75108bb1d6b4474928532`、`de15c8af1ded8b1297468123be7a7d2f81ab5b6f667239c5a2668c5de501860f`、`6a269eca7205f256016d3b95467af59dab71b4fe8563d4636b04df5e4e716076`、`18781e71046f8e7afd8bde39c397f3692dabb1ec29c4ce0c934165abb5a2fe6f`
- cohort builder `4/4`、analyzer `6/6`、verifier `2/2`；权威远端 RQ2 全目录更新为 `139/139`
- 论文相关章节已同步并在权威远端重建 `paper/cose/full_draft.md`，原始 `wc -w=16,651`；package validator 共运行 `107` 项检查，silver/affected_versions claim-boundary lints 通过，失败项仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log

当前效果与下一步：

- XWiki 单例中的 graph 构件已扩展到三个生态和三类 identity edge，证明同一 fail-closed schema 能处理一组跨 artifact 的等边界表达；这比重复 prompt review 提供了更具体的可执行构念
- `8/8` 由 equality selector 预先限定，且 source 已揭封并受非人工标签条件化，因此只能报告 graph coverage/construct consistency，不能报告 accuracy、generalization 或 human gold
- 下一步应保持 schema 不变，转向非等边界 containment、multi-artifact 与未见生态 development rows；通过后才值得冻结新时间 cohort。现实人工 shared calibration 与全量签收门禁仍未满足

### 9. 已完成并在权威远端验证：非等边界 artifact-lineage no-go v1

本次完成：

- 保持通用 graph schema 与 equal/subset/overlap→taxonomy map 不变，新增非等边界 raw selector；它排除已用于 graph 开发的 XWiki 行，从 v2 source 中选择所有剩余双边非空、单 subject、跨 artifact 且 raw interval signature 不相等的 `5` 行，不读取 reviewer 文件或 consensus label
- 冻结 Graylog Maven Central、phpMyFAQ Packagist、Pimcore Packagist、Jenkins plugin repository 和 Electron npm 的 `7` 个 catalog/POM 响应，共 `14` 个 response/metadata cache files；正式分析按 stable parseable released-version catalog 枚举 affected sets
- 在运行前固定 advancement threshold：projection coverage 至少 `4/5`，development candidate 与两份封存 A/B 同时一致至少 `4/5`，且 non-human boundary 必须保持；任一失败均为 no-go
- 正式结果 projection `4/5`：phpMyFAQ 为 NVD `108` < GHSA `112`，GHSA-only 为 `3.1.15`--`3.1.18`；Pimcore 为 NVD `1` < GHSA `206`，两者均得到 `incomplete` 并与 A/B 一致。Electron Packager 为 `1=1`、Jenkins Teams Webhook 为 `2=2`，catalog graph 得到 `representation_discrepancy`，但 A/B 均按 singleton/list 对 interval 的 intension 判为 `incomplete`
- Graylog 因 Maven Central catalog 不含 advisory 中 `6.3.0-alpha.1` 至 `6.3.0-rc.2` prerelease boundaries 而 fail-closed `uncertain`；最终与两份 A/B 同时一致仅 `2/5=0.4`，低于 `0.8` 固定门槛，advancement status 为 `no_go_non_equal_graph_unstable`

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_artifact_lineage_non_equal_cohort.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_artifact_lineage_non_equal.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_artifact_lineage_non_equal.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/artifact_lineage_non_equal_v1/`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/artifact_lineage_non_equal_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_calibration_v2/artifact_lineage_non_equal_v1/`
- 首次结果因未处理 Composer 2.0 minified metadata 的省略字段而只投影 `2/5`，保留在 `artifact_lineage_non_equal_v1_failed_minified_parser_20260719/`；第二次结果因等价 prerelease 拼写共享排序键而无法确定性重算，保留在 `artifact_lineage_non_equal_v1_failed_nondeterministic_sort_20260719/`。两项均为机械实现缺陷，正式版分别修复省略字段继承与原始 token 二级排序，不改 set relation 或 taxonomy map

验证：

- 独立 verifier 核对 cohort seal、contract/code/reviewer hashes、固定 `14` 文件证据 inventory、URL/status/body hashes，并确定性重算五条 release sets、candidate、固定 thresholds、Markdown 与 no-go gate，返回 `0`
- cohort、cohort manifest、analysis、Markdown、analysis manifest SHA-256 分别为 `fcecd960cd4bbdace4dacfc30f5d47d85441e53b08c63836f9eec19a73205e23`、`107a5314d79b90ea2397b9cca00925f6aac184c256663ce0e8537fd1f8ecb96c`、`61ebef9870d9d0ef34d1bd6289db223cb3ee96172d21d3b3e8e3504f53cbceeb`、`5cfe73a9f6cc66e3479cfbbd10064fa3423721e7755ef02e903c788e2a3bb814`、`ce11a0b914fef58e81b2bd0c8b89acb974e59300acc009e15e1769bbcc9eadbd`
- non-equal cohort builder `3/3`、analyzer `6/6`、verifier `2/2`；权威远端 RQ2 全目录更新为 `150/150`
- 论文相关章节已同步并在权威远端重建 `paper/cose/full_draft.md`，原始 `wc -w=16,987`；package validator 共运行 `107` 项检查，silver/affected_versions claim-boundary lints 通过，失败项仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log

当前效果与下一步：

- graph 已能证明 artifact identity 和当前已发布版本集合关系，但不能自行决定 taxonomy 应比较 frozen extensional release set，还是 source interval 的 intensional coverage；Electron/Jenkins 的分歧正好隔离了这一字段合同
- `2/5` 是与同模型家族封存 A/B 的 construct consistency，不是真实准确率；当前 no-go 同样不能证明 A/B 或 catalog graph 哪一方正确
- 下一步应由现实人类 shared calibration 对这两条和 Graylog 证据缺口明确选择 extensional/intensional/temporal contract；合同冻结前不再修改 relation map，也不消耗新时间 cohort

### 10. 已完成并在权威远端验证：snapshot-extensional Codex 候选合同与 InLong 多构件诊断 v1

本次完成：

- 显式冻结 `codex_expert_contract_candidate`：比较同一数据快照中 source-owned catalog 已发布版本的有限外延集合；`introduced=0` 不生成假想版本，未来版本风险单列为 temporal stability；该合同保持 `label_is_human=false`、`production_switch_allowed=false`
- 固定多构件规则：每个 component coordinate 必须由官方 catalog 和同版本 product-parent POM 绑定，逐组件独立求 affected set，再以并集形成 product affected set；必须保留每个组件集合和 heterogeneity flag，任一 component 未绑定则拒判
- label-independent selector 从已揭封 v2 source 中稳定选择唯一一产品对多构件行 `rq2_typing_holdout_v1:548`（`CVE-2023-30465`）；selector 不读取 reviewer 文件或 consensus label，上游 source 受非人工 consensus 条件化的边界写入 seal
- 对 `org.apache.inlong:manager-pojo` 与 `org.apache.inlong:manager-service` 各冻结 Maven catalog 及 `1.4.0/1.5.0/1.6.0` 三个 POM，共 `8` 个官方响应、`16` 个 response/metadata cache files。所有 POM 均通过 `org.apache.inlong:inlong-manager` 同版本父模块和 Apache InLong project name 绑定 product edge
- 两个组件的 frozen affected set 均为 `{1.4.0,1.5.0}`，heterogeneity 为 false；GHSA component union 与 NVD product point set 相等，技术 projection gate `1/1`，得到非人工 `representation_discrepancy` development candidate
- 封存 A/B 均为 `incomplete`，因此 candidate 与两者同时一致为 `0/1`。正式 diagnostic status 为 `snapshot_extensional_projection_supported_human_resolution_required`，不改前一轮 `no_go_non_equal_graph_unstable`，不允许 accuracy、human-gold 或 production-switch claim

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/affected_versions_snapshot_extensional_codex_candidate_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_artifact_lineage_multi_component_cohort.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_artifact_lineage_multi_component.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_artifact_lineage_multi_component.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/artifact_lineage_multi_component_v1/`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/artifact_lineage_multi_component_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_calibration_v2/artifact_lineage_multi_component_v1/`

验证：

- 独立 verifier 核对 cohort seal、候选合同/code/reviewer hashes、固定 `16` 文件证据 inventory、URL/status/body hashes，并逐组件重算 product edge、affected sets、union、relation、candidate、Markdown 和非人工边界，返回 `0`
- contract、cohort、cohort manifest、analysis、Markdown、analysis manifest SHA-256 分别为 `42c8357953eb570cdcf6824ee60497a8493f8fbdd8c2954809a79566754f7634`、`8041eff4dae1de98a26d6033582850b7c78891d0dc19414d4f2f16174b6b71e1`、`64609b57398982eb121ce3500ab81201e6634d2a59c68529915e36bf4b1d36b5`、`5e7ea3ab111577d5eccc609034b81d090a9ae49df6716c9ab8a1e8812b8a9af0`、`066571e7a733daf2d74b7cd79028aa442638c9e6e970177ecb051b0626257a25`、`79db34d4214902be872fa5690f7147dda540f7b30d455719aed9fa02bcd47767`
- multi-component cohort builder `3/3`、analyzer `3/3`、verifier `2/2`；权威远端 RQ2 全目录更新为 `158/158`
- 论文相关章节已同步并在权威远端重建 `paper/cose/full_draft.md`，原始 `wc -w=17,283`，SHA-256 为 `4486c5a6cae90578c8a3787c2ce2f3ed3b7d83e2e71bf19c61cc4fc698273c59`
- package validator 共运行 `107` 项检查，silver/affected_versions claim-boundary lints 通过；失败项仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果与下一步：

- 该单例说明 one-product-to-many-components 可以在不丢失组件级集合的情况下执行 snapshot-extensional projection，也说明多构件结构本身不能消解 extensional/intensional 合同冲突
- 样本只有一条且两个组件范围相同，没有验证 differing-component-range、component heterogeneity、未见生态或真实人工正确性
- 下一步应由两名不同现实人员在 shared calibration 中明确选择或改写字段语义并由作者签收；随后固定异构组件范围和未见生态 development cases。通过这些 construct gates 前不冻结生产 comparator 或新时间 cohort

### 11. 已完成并在权威远端验证：异构多包未见生态 artifact-lineage no-go v1

本次完成：

- 直接扫描完整 `data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl`，在 `8,066` 个匹配对范围内发现 `486` 个一 NVD subject 对多 GHSA package 的 raw 候选，其中 `237` 个按 canonical component range signature 异构
- 在证据抓取前固定 selector：对此前未覆盖的 `NuGet`、`PyPI`、`crates.io`，分别要求一 NVD subject、恰好两 GHSA package、单一生态、组件 range signature 不同、每 claim 至多三段、非零边界可解析，再取 SHA-256(`cve_id`) 最小行。eligible counts 为 `5/12/6`，稳定选择 `CVE-2023-21893`、`CVE-2023-39631`、`CVE-2025-48888`
- selector 不读取 reviewer 或 consensus 文件，source 为完整 aligned input，明确记录 `selection_uses_reviewer_labels=false`、`selection_uses_non_human_consensus=false`、`upstream_source_conditioned_on_non_human_consensus=false`
- 在抓取证据前冻结 graph extension 和 advancement gate：至少 `2/3` 行完整投影、至少两个生态通过、非人工和 label-independent 边界保持，否则 `no_go_unseen_ecosystem_graph_unstable`
- 冻结 `14` 个官方响应、`28` 个 response/metadata cache files：Oracle 两个 NuGet catalogs 与 NUSPEC、Oracle CPU；LangChain/numexpr PyPI catalogs 与 LangChain `0.0.245` metadata；deno/deno_runtime crates catalogs 与四个 Deno release dependency records
- 三条均保留组件级 frozen affected sets 且 component heterogeneity 为 true，但产品投影全部拒判：NuGet 两包分别枚举 `22/26` 个 affected releases，起始 boundaries 与 NVD `19c/21c`→package release mapping 缺失；PyPI 为 langchain `309`、numexpr `47`，但 `numexpr>=2.8.4,<3.0.0` 仅是 dependency constraint；crates.io 两组件各 `62`，但 `2.1.13/2.2.13` 不在 `deno` crate catalog，且 deno_runtime 仅由 caret constraints 约束
- 正式结果 projection `0/3`、candidate `3 uncertain`、passing ecosystems `0`，advancement status 为 `no_go_unseen_ecosystem_graph_unstable`。该结果不修改 InLong 或前一轮 non-equal no-go，也不产生 reviewer accuracy 或 human-gold claim

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/affected_versions_unseen_ecosystem_graph_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_artifact_lineage_unseen_ecosystem_cohort.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_artifact_lineage_unseen_ecosystem.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_artifact_lineage_unseen_ecosystem.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/contract_calibration_v2/artifact_lineage_unseen_ecosystem_v1/`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/artifact_lineage_unseen_ecosystem_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_calibration_v2/artifact_lineage_unseen_ecosystem_v1/`

验证：

- 独立 verifier 核对 full-aligned source/cohort/contract/code hashes、固定 `28` 文件 evidence inventory、URL/status/body hashes，并确定性重算 registry catalogs、component sets、edge classes、failed checks、Markdown、boundary 与 advancement gate，返回 `0`
- contract、cohort、cohort manifest、analysis、Markdown、analysis manifest SHA-256 分别为 `7fc90009f2b64d09ba119dc3c3a5d4644603ef6516af4ca218692450a100c5a6`、`377e1dde6dd0450d6f499a58d1960209b2b3f40069f7c7e613c2315ebdd30007`、`83c847c82497a0b055ee2722b19d1618c1bc3211332fb78c53f633d04c4b71ea`、`de26c27290d9a2adfdb69686cbd410a6ad2e99aad4d6ce815d43cf0458d65d98`、`0492e0bf020eff3bf5551b48df682ed154ba07d1252eda636a50a205c8208164`、`5ec10bb95ce67417285a63cdecb6e3b56b2fac8c52fd10f74712f57153698fdd`
- unseen-ecosystem cohort builder `4/4`、analyzer `5/5`、verifier `2/2`；权威远端 RQ2 全目录更新为 `169/169`
- 论文相关章节已同步并在权威远端重建 `paper/cose/full_draft.md`，原始 `wc -w=17,596`，SHA-256 为 `ebb0c4a1bb670605cd0f1a29735c468485eb562a95928cc91ec55f8079f03b36`
- package validator 共运行 `107` 项检查，silver/affected_versions claim-boundary lints 通过；失败项仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果与下一步：

- 新结果把“multi-component 未测试”推进为更具体的负面结论：package identity、component affected sets 和 shared repository/dependency evidence 仍不足以形成 product release union，必须区分 coordinated component、dependency constraint、parallel distribution 与 alternative package
- 该 0/3 no-go 来自固定 label-independent full-aligned selector，避免了此前 calibration 上游非人工 consensus 条件化；但它仍是 post-unsealing development diagnostic，不是总体发生率或真实正确性估计
- 下一步先由现实人员固定字段语义，同时明确何种 lockfile/build manifest/vendor mapping 才算 deterministic total component→product release map；没有这种证据时不再通过增加 registry parser 强算关系，也不冻结新时间 cohort

### 12. 已完成并在权威远端验证：Deno 官方 Cargo.lock product-lineage 恢复诊断 v1

本次完成：

- 在抓取新的 GitHub release/lockfile 证据前冻结 post-no-go 合同，只复用未见生态队列中 label-independent 的 Deno `CVE-2025-48888` 行；合同固定 product release source、核心窗口、前后锚点、精确 runtime 映射、单调性、边界 containment 和 `1/1` advancement gate
- 明确 product coordinate 使用官方 `denoland/deno` GitHub Releases，而不是 crates.io `deno` package；分页按每页 100 条抓到空页，固定响应数量为 `100/100/100/86/0`，其中有 `381` 个 eligible stable releases
- 核心窗口覆盖 `1.41.3` 至 `2.3.2` 共 `69` 个产品版本，并加入直接前驱 `1.41.2` 和直接后继 `2.3.3`；对全部 `71` 个官方 tags 抓取并解析 committed `Cargo.lock`
- 每个锁文件恰有一个 exact `deno_runtime` package version，且 `71/71` 均存在于冻结 crates.io catalog；版本序列单调不降。前驱映射 `0.149.0 < 0.150.0`，后继映射 `0.213.0 >= 0.212.0`，因此 runtime claim `[0.150.0,0.212.0)` 被两侧锚定
- 在同一官方 product domain 上，NVD/direct Deno 集合有 `63` 个 releases；GHSA runtime 投影有 `66` 个，和 direct 集合并集后为 `68` 个。runtime-only additions 为 `2.1.13`、`2.1.14`、`2.2.13`、`2.2.14`、`2.2.15`，得到 `nvd_subset_of_ghsa` 与非人工 `incomplete` development candidate

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/affected_versions_deno_lockfile_recovery_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_deno_lockfile_recovery.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_deno_lockfile_recovery.py`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/deno_lockfile_recovery_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/contract_calibration_v2/deno_lockfile_recovery_v1/`

验证：

- 证据 manifest 固定 `154` 个 cache files：5 页 GitHub release response/metadata、1 份 crates.io runtime catalog response/metadata，以及 71 份 Cargo.lock response/metadata
- 独立 verifier 不调用 analyzer 的 release/lock/set 函数，重新核对所有 input/output/cache hashes 与 URL/status/body hashes，重建 release inventory、anchors、71 对 exact mappings、集合和 Markdown，返回 `0`
- contract、analyzer、verifier、analysis、Markdown、manifest SHA-256 分别为 `9bc7b7cf93cf8bf04d90f0103f9d17d026616555b7b4b12300380561cf6c4044`、`3ff74083af1b7f7946bbfd9f68711274aee193269e11337c34f18f3d8d389a98`、`9d9e8a993ade444c6ce152544cfb30719bc07574e55782805fa57e89f62a6ea6`、`de08f6f4cebfb85f4a7378ff8296770b9f28b9619b935815346e1c46a47243f2`、`0def2fd2dce1a8edf5c7ebf03fc17304d4a5b3684b6c8e3d2dd1b4bf54622457`、`e9be672587a0811bcc6ae698cdc1ac88d78be324e095e9dc0d9fad0c1060913a`
- analyzer `5/5`、verifier `3/3`；权威远端 RQ2 全目录更新为 `177/177`
- 已更新 COSE setup/results/discussion/threats/conclusion/submission readiness 并在权威远端重建 `paper/cose/full_draft.md`，原始 `wc -w=17,952`，SHA-256 为 `456dc3e821ff017379b472e7408f58f4f1f1d9b85476ba5d69b26494261354f0`
- package validator 共运行 `107` 项检查，silver/affected_versions claim-boundary lints 通过；首次运行因半开区间方括号触发 citation parser 假阳性，改写为等价不等式后恢复通过。最终失败项仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果与下一步：

- 该结果证明 parent 0/3 中 Deno 的拒判不是永久结构性失败：dependency constraint 本身不足，但官方 tag 下 exact build lock 可以建立 deterministic product→runtime edge，并在固定窗口恢复集合投影
- 这仍是揭封后、单 CVE、单项目、由 Codex 冻结合同的恢复性诊断；`incomplete` 是 `label_is_human=false` candidate，不是 human gold、accuracy、reviewer agreement 或 Rust ecosystem generalization
- NuGet parallel distribution 与 PyPI non-exact dependency 仍未恢复。现实人员仍需决定 extensional/intensional/temporal 范围语义，并确认 lockfile 是否是该字段可接受的权威映射；只有现实人工门禁和完整 construct gate 通过后才冻结新时间 cohort

### 13. 已完成并在权威远端验证：RQ2 103 条非严格行的第三盲审与合并门禁 v1

本次完成：

- 在 A/B 结果揭封后，仅从原始盲 worklist 抽取 `103` 条非严格行，生成 reviewer C 的独立盲审队列；C 不接收 baseline、A/B 标签、consensus 或采样优先级，继续使用原冻结 prompt
- 在 C 运行前固定合并规则：只有至少两份 qualified votes 给出同一 determinate label 才解决；qualified vote 必须非 uncertain、confidence 非 low 且 `needs_human_review=false`
- 在 C 运行前固定 advancement gate：103 条中解决率至少 `0.70`，且合并后的全 cohort candidate coverage 至少 `0.975`；任何结果都保持 `label_is_human=false`
- 使用 `codex-cli 0.144.4`、`gpt-5.5`、medium reasoning、read-only sandbox 和全新 ephemeral sessions 完成 C 的 `103/103` 行；5 个 batch 的请求与成功响应日志均保留
- 合并器逐行连接 sealed worklist、A/B 原结果、C 输出和 C request log，并保留首次未绑定 request log 的旧结果目录，不回写旧 seal

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_typing_tiebreak.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_rq2_typing_tiebreak.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_typing_tiebreak.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/tiebreak_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/tiebreak_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/tiebreak_v1_pre_request_log_binding_20260719/`

验证：

- sealed C worklist 为 `103` 行：affected_versions `58`、cwe_ids `21`、references `13`、severity `11`；worklist 与 manifest SHA-256 分别为 `3af462fc3ba42d0223399b1dc001ff554796b49741aca3f2f5ae3fbe81e55e26`、`0ae8b7f1a076c9ded28a92718fa77a65ced2eaf3049f323eedf75617ac5f5f74`
- C 输出 `103/103`，请求日志精确包含 5 组 request/response_success、103 个 sample ID 且保持 sealed input order；C sessions 与 A/B sessions 零交集
- C 输出、request log、candidate consensus、summary、agreement metrics 与结果 manifest SHA-256 分别为 `70834d66720c3bffd7e9d9a0db73c6d6e32fbdeaa26b6168434a0121a4985164`、`8596896990871e19b85470b840a760292489c6dfd90c92a8e84980786c330e5f`、`b3abca3b6e1ad4559b2781f7275cf1656122c6d843df5cdeedfa8d540a40ab62`、`a873316fa8d06b0da52be778d9743b54b24df8a00565e717ca9bf9da89e2a9c9`、`bd1f99c44b6f58431d17715a357ca0a3cfc9ac29819b7b48fff254eecc850057`、`85fb1a4e7fb003094aaf371db38b64da8d98aef9d7c61c001ff7e8769f9b4eb2`
- 第三盲审解决 `66/103`（`0.6408`），合并后的非人工 candidate 为 `1,213/1,250`（coverage `0.9704`）；两项均低于预先固定门槛，状态为 `no_go_non_human_tiebreak_coverage`
- 合并后每字段 candidate coverage：affected_versions `222/250`、cwe_ids `244/250`、published `250/250`、references `248/250`、severity `249/250`
- current baseline 与 1,213 条非人工 candidate 的 agreement 为 `974/1,213`（`0.8030`），macro-F1 `0.8156`，全 cohort 下界 agreement `0.7792`；这是 same-model-family candidate agreement，不是 human-gold accuracy
- 独立 verifier 不调用 merge 主函数，重新核对 source/output/request hashes、session 隔离、逐行 qualified-vote 规则、字段统计和 gate，返回 `0`；新增 focused tests 通过，权威远端 RQ2 全目录更新为 `185/185`
- 已更新 COSE setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`；原始 `wc -w=18,430`，SHA-256 为 `56cddafc25daf784ff2af6fd4308e9b40414fa814f864ec7eb90997c61722a90`
- package validator 共运行 `107` 项检查；新增 tiebreak 句子的 silver/affected_versions claim-boundary lints 修正后通过。最终失败项仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- 两个原始 blind pass 的 103 条非严格行中，第三 pass 可按固定多数门禁解决 66 条，但不能达到预设覆盖率；没有降低门槛，也没有把未解决行强制赋值
- 剩余 `37` 条集中在 affected_versions `28`、cwe_ids `6`、references `2`、severity `1`；其中 `17` 条三份结果均 uncertain，另有 `7` 条三份 qualified votes 仍产生标签分裂
- 该分布支持“证据不足或字段合同分歧是主要瓶颈”的开发诊断；继续增加同模型家族盲投票缺乏明确收益，不能替代证据增强或现实人员裁决

未验证：

- C 与 A/B 虽然 session 隔离，但仍使用同一 Codex 模型家族、同一 prompt 和同一快照；三者不是独立现实专家
- tiebreak 是 A/B 揭封后的选择性流程，不能作为预注册的全 cohort 独立评估，也不能把 `0.8030` 报告为 accuracy
- 37 条未决行尚未接受新证据或现实人员签收；全量 human packet 仍为 `1,250 pending / 0 signed`

下一步：

- 不启动第四个同模型盲投票；先生成 37 条未决 review packet，按 triple-uncertain、qualified-vote split 和 partial-qualified 分组，保留原盲行与三份候选但不加入 baseline
- 优先为 28 条 affected_versions 补充 product/package identity、范围语义和 lineage evidence，再处理 6 条 CWE、2 条 references 和 1 条 severity
- 最终标签仍须由两位不同现实人员独立复核并由作者签署；只有通过完整人工门禁后才能生成 canonical human gold

### 14. 已完成并在权威远端验证：RQ2 37 条未决行的证据增强双审 no-go v1

本次完成：

- 在抓取任何新证据和生成 D/E 输出前，冻结 37 条 post-tiebreak 未决队列、URL 排序/变换规则、双审合同与 advancement gate；队列固定为 affected_versions `28`、cwe_ids `6`、references `2`、severity `1`
- 固定 prior-vote 诊断分组：zero-qualified `17`、one-qualified `10`、two-qualified-split `3`、three-qualified-split `7`；author-only triage 保留 A/B/C 候选和分组但不含 baseline，D/E 盲文件不含 A/B/C、candidate、vote count、baseline 或 selection group
- 只从原始 NVD/GHSA reference context 中确定性选择每行最多 6 个 URL；GitHub commit/pull 可取 patch，blob 可取 raw，但 reviewer 可引用的仍是原始 URL。正式 manifest 绑定 100 个唯一 cache files 及全部 input/output hashes
- 在证据抓取前固定门槛：successful non-empty evidence rows 至少 `0.75`、D/E evidence-qualified strict resolution 至少 `0.40`、全 cohort combined candidate coverage 至少 `0.982`；失败后不得降门槛或回退到 A/B/C 多数票
- D/E 使用同一 evidence prompt、相反 sealed input order、`codex-cli 0.144.4`、`gpt-5.5`、medium reasoning、read-only sandbox 和全新 ephemeral sessions；各完成 `37/37`，均为 `12/12/12/1` 四个 batch，无 request/validation error

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_typing_unresolved_evidence_secondary_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_typing_unresolved_evidence_review.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_typing_unresolved_evidence_secondary.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_rq2_typing_unresolved_evidence_secondary.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_typing_unresolved_evidence_secondary.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/typing_unresolved_evidence_secondary_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/`

验证：

- 37 行中 `28/37` 至少有一条 successful non-empty evidence，rate `0.7568`；104 个行级 evidence records 的状态为 `88 ok / 3 http_403 / 3 http_404 / 10 timeout`，通过固定 evidence-availability 门槛
- D/E exact label agreement 为 `25/37`，但其中 `19` 行是双方共同 uncertain；base strict 与 evidence-qualified strict 均为 `6/37`（`0.1622`），低于固定 `0.40` 门槛，没有 strict row 因 citation gate 被二次剔除
- evidence-qualified strict 分字段为 affected_versions `0/28`、cwe_ids `4/6`、references `1/2`、severity `1/1`；6 条新候选分别为 4 条 CWE、1 条 references 和 1 条 severity，没有 affected_versions 被强制解决
- 合并后的非人工 candidate 为 `1,219/1,250`（coverage `0.9752`），仍低于固定 `0.982`；remaining unresolved 为 `31`，其中 affected_versions `28`、cwe_ids `2`、references `1`
- current baseline 与 1,219 条非人工 candidate 的 agreement 为 `977/1,219`（`0.8015`），macro-F1 `0.8137`，full-cohort lower-bound agreement `0.7816`；这些是 same-model-family candidate agreement，不是 human-gold accuracy
- D/E request logs 各精确包含 4 组 request/response_success，session sets 互斥且与 A/B/C 零交集；独立 verifier 重算 hashes、request schedule、review contract、citation gate、combined labels、metrics 和 advancement gate 后返回 `0`
- contract、prompt、builder、merge、verifier、sealed manifest、D、E、D request log、E request log、summary、combined candidate、metrics、result manifest SHA-256 分别为 `e73584ee0c9b7323328567ef81d0275f594772007a6c2b8c39f34b48e795ddc0`、`99757c90787bbff71f707bf63deb68cf00302c8061faa55550eb4aba0e500aa7`、`bf17db31d5b18f84d9bb418a2c1bb68f9c89c3f9a10dedd5c27d06cbc0efa086`、`0cdcb216c1b16a753810ea24dc752000f1ecefea0aff9b46d273bc35f4d77f85`、`2981a5d6b084bc589ba493593d13e60edb8250229e731f0223b8813309bb29ed`、`3c694341991aca4d84c8e36ac42616caa55642183ebc1cc5ec70a9dc174b0d09`、`a7208c0274567e5fbbc5c50d9f99e9629b46592085d9e63cdfa4288b78cb7408`、`0945c904dec8aeb8ede909400111f8ef6b2fdc37c345adafe1153b88ef40e8d3`、`2fdf0c0604334f8d661c16f8a48ed0bf8969f1ec922d8c1f824c478ad173685e`、`67d3a6d77a6b1e21e07915a949b169cec94138e2eb87927c528e249cc9d5cc38`、`4cdcb28e48ad270d1897e73e3d1f2cb35b6ab20d8017949ca94bf6cd3339f8e0`、`cc448df2bb997351d5e2395652f75b17e98df315b4c5816a750a9907c6da21e9`、`0803eaaace3171c21760bf389789b72d99d4a57e643a910f657f89c1da49821c`、`bbb8144199229178bf58878264e9ffdb4779995e53fc82517a828ff8491e901f`
- 新增 focused tests `10/10`；权威远端 RQ2 全目录更新为 `195/195`
- 已更新 COSE setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`；原始 `wc -w=18,896`，SHA-256 为 `b1f2fb02bedd129483a627940d072192bf451802987b2f234db02132ccd322c1`
- package validator 共运行 `107` 项检查，silver/affected_versions claim-boundary lints 与 citation checks 通过；失败项仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- 冻结 URL evidence 可把 37 条中的 6 条变成严格非人工候选，并将 combined coverage 从 `0.9704` 提到 `0.9752`，但预设 gate 仍是 `no_go_non_human_evidence_secondary`
- affected_versions 的 `0/28` 是最重要的负面结果：普通 advisory、commit、issue 和 release 页面即使抓取成功，也通常不能建立完整 product/package identity、全部范围端点、branch/backport 或 product-release mapping
- exact agreement `25/37` 不能当作解决率，因为 `19` 条是共同 uncertain；该结果支持保留 abstain，而不是把共同拒判改写成一致标签

未验证：

- D/E 仍与 A/B/C 属于同一模型家族；session 隔离不等于独立现实专家，也不产生 human gold
- URL selector 和 evidence contract 都是在 A/B/C no-go 后设计，37 行又是选择性困难子集；`6/37` 不是无偏总体成功率
- 28 条 affected_versions 尚未获得逐项目 release graph、lockfile/build manifest 或 vendor product-package mapping；现有通用 URL 文本不能证明最终标签

下一步：

- 不对 31 条 remaining unresolved 再做通用 URL 抓取或同模型裸投票；优先把 28 条 affected_versions 按 product/package mismatch、branch/backport、prerelease/open-bound 和 multi-component 分层
- 仅对存在可冻结 total mapping 的项目构建 release/manifest/lockfile graph；没有 edge authority 时继续 abstain，不从版本邻接或依赖范围强推集合关系
- 2 条 CWE、1 条 references 与全部 28 条 affected_versions 最终仍需现实人员按共享字段合同独立复核和作者签署

### 15. 已完成并在权威远端验证：28-row edge-class 审计与 Mattermost Git-tag graph no-go v3

本次完成：

- 从 sealed D-side blind worklist 固定读取全部 `28` 条 affected_versions；先计算结构特征、项目族、eligibility 和 ranking，完成选择后才加载 D/E 作为 diagnostic，明确 `selection_uses_reviewer_labels=false`
- 将 28 条分为 `16` 个项目族；重复族固定门禁只保留 Mattermost、LF Edge EVE、Hutool，结构分数分别为 `14/9/8`。Mattermost 固定样本为 `CVE-2025-22449` 与 `CVE-2025-27933`
- Mattermost v1 因 GitHub Releases 第 1--10 页均为 100 条且第 11 页 HTTP 422，在 set analysis 前停止；v2 复用冻结前缀后发现 `10.3.0`、`10.4.0` 不是其中的 GitHub Release objects，也在 manifest/set analysis 前停止。两次协议失败均显式保留，没有降低门槛后伪装为原合同结果
- v3 在新证据抓取前冻结 19-token 官方 Git-tag manifest domain、两个 pseudo commit 的 SHA/timestamp/module/ancestry gates、legacy tag manifest gate 与 family-level `2/2` advancement threshold；HTTP 404、diverged 和未知 compare status 一律不填补
- 两个只读 agent 独立比较结构可判定性与论文增益/风险，均把 Mattermost 置于 LF Edge EVE/Hutool 与 Adobe/Magento 之前；最终可执行选择仍由独立 verifier 可重算的 label-independent 规则决定，而不是 agent 投票

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/affected_versions_unresolved_edge_class_audit_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/affected_versions_mattermost_release_graph_contract_v{1,2,3}.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_unresolved_affected_edge_classes.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_unresolved_affected_edge_classes.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_mattermost_release_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_mattermost_release_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/affected_versions_edge_class_audit_v1/`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/mattermost_release_graph_v{1,3}/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/mattermost_release_graph_v3/`

验证：

- edge audit 独立 verifier 从 sealed worklist 与 prior official graph 重算全部 28 条 row features、16 个 family aggregates、eligibility、score、ranking 与 D/E diagnostic，确认首选 `mattermost` 且选择不使用 reviewer labels
- v3 冻结 `80` 个官方 sources，对应 `160` 个 response/metadata cache files；`19/19` 当前 tag 的 `server/go.mod` 均精确声明 `github.com/mattermost/mattermost/server/v8`
- 两个 pseudo-version 均解析到唯一 full SHA，12-character prefix、UTC committer timestamp 与 exact-commit `server/go.mod` 全部通过：`64c566a8280b...` 对应 `2025-01-02T08:18:31Z`，`e644e3c8e393...` 对应 `2025-02-18T13:50:18Z`
- `CVE-2025-22449` 的 19 个 tag compare 全为 `diverged`；`CVE-2025-27933` 为 `3 ahead / 15 diverged / 1 identical`。legacy repository 在固定 domain 中 `0/19` exact tag manifests 绑定
- 两行分别失败 `pseudo_ancestry_total`，以及 `pseudo_ancestry_total + legacy_module_mapping_total`；均保留 `uncertain`、不计算 set relation，family gate 为 `0/2`，状态 `no_go_mattermost_release_graph_unstable`
- cache-only verifier 不调用 analyzer，从 160 个哈希绑定文件独立重算 domain、module identities、commit records、38 个 compare mappings、row gates 与 family gate 后返回 `0`
- 新增 focused tests `19/19`；权威远端 RQ2 全目录更新为 `214/214`
- 已更新 COSE setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`；原始 `wc -w=19,523`，SHA-256 为 `a4a73c5f87f25e8a25b751a7045bcbdb595c4de1529d4fe9ab0035d8b97e2151`
- package validator 共运行 `107` 项检查，新增 claim-boundary/citation checks 通过；失败项仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- 该实验把“generic URL evidence 不足”进一步定位为 edge-specific no-go：同一产品的 `19/19` manifest identity 与精确 pseudo commit 仍不能跨分支/backport 建立 total ancestry，legacy coordinate 也没有 tag-level total mapping
- 未新增任何 affected_versions candidate；combined candidate 仍为 `1,219/1,250=0.9752`，remaining unresolved 仍为 affected_versions `28`、cwe_ids `2`、references `1`
- v1/v2 的失败表明 GitHub Releases pagination 与“边界版本必为 Release object”都不能作为通用默认；v3 的 0/2 又表明 Git-tag identity 仍不是 release-set projection

未验证：

- family rules、分数与三版 Mattermost 合同都在上游 no-go 揭封后设计；不能据此估计项目族成功率、Go 生态失败率或 human accuracy
- 固定 19-token domain 是 branch-window mechanism test，不是 Mattermost 全版本 catalog；diverged 说明当前 pseudo commits 不能按该 ancestry 规则 total 投影，不证明 GHSA 或 NVD 哪一方事实错误
- 两个 agent、D/E 与本轮 Codex 均不是现实人员；所有 candidate boundary 保持 `label_is_human=false`

下一步：

- 按冻结 ranking 进入 LF Edge EVE；先要求 EVE OS release、LTS/backport 与 Go pseudo-version 的 total graph，不能仅凭 repository identity 或 advisory text
- Mattermost 两条保留给现实人员选择 extensional product-release、intensional module-commit 或显式 temporal/backport 语义；没有新 edge authority 前不继续改合同追求通过
- 继续完成 2 条 CWE、1 条 references 与 28 条 affected_versions 的现实双人复核和 author signoff

### 16. 已完成并在权威远端验证：LF Edge EVE 207-tag release/LTS graph no-go v1

本次完成：

- 按 28-row edge audit 的冻结第二顺位读取 `CVE-2023-43630` 与 `CVE-2023-43632`；sample IDs、NVD product intervals 与 GHSA pseudo upper bounds 均由 sealed D-side worklist 和 manifest 绑定
- v1 前只读 protocol discovery 明确披露：官方 tag grammar、207-token domain、根 `go.mod` 缺失、nested `pkg/pillar` module、非 Go `pkg/vtpm` build component，以及两个 pseudo commit 的 changed paths 均在冻结前已知；因此 `candidate_promotion_allowed=false`，不能把本轮写成盲测成功率
- 冻结 `3.0.0` 至 `10.1.0` 的全部 207 个 `MAJOR.MINOR.PATCH` / `-lts` tags，排除 `4.9.1-uefi`；family advancement threshold 固定为 `2/2`
- 用 filtered official Git clone 生成 content-addressed commit pack，替代 414 次 tag-to-pseudo compare API 调用；独立 verifier 在空 bare repository 中运行 `index-pack`、绑定 official refs，并完全离线重算 ancestry、module/component、patch-path、anchor 与 row gates
- 保留两次 verifier 实现修正：首次错误地把 JSON `sort_keys` 后的字典序当 domain 顺序，改为显式 fixed-domain 加 207-key set；第二次 `git show` 在 commit-only pack 中读取未打包 parent tree，改为直接解析 hash-bound commit object 的 committer epoch。两次修正后均重跑 analyzer 与 verifier，没有修改实验门槛

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/affected_versions_lf_edge_eve_release_graph_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_lf_edge_eve_release_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_lf_edge_eve_release_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/lf_edge_eve_release_graph_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/lf_edge_eve_release_graph_v1/`

验证：

- 权威环境再次确认为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）
- 固定 Git snapshot 包含 `207` 个 product tags、`10,182` 个 reachable commits 和 `11,070` 个 required objects；pack 大小 `2,669,353` bytes，SHA-256 `554947932b5d74bfac48c7cf922b31650c2ec3075365cc00b06735532f7741d0`
- 两个 pseudo suffix 均绑定唯一 full SHA 与精确 UTC committer timestamp：`d9383a7ee4e1...` / `2023-01-26T06:57:59Z`，`977f42b07fa9...` / `2023-05-19T07:27:51Z`
- public GitHub advisory API 的两份 snapshot 均只暴露 historical root package `github.com/lf-edge/eve` 与 pseudo first-patched version，没有 repository advisory UI 中的 component paths 和 product/LTS patched anchors；两种 interface 没有被互相覆盖
- `CVE-2023-43630` 根 module 为 null，owner manifest 正确绑定 `github.com/lf-edge/eve/pkg/pillar`，pseudo patch 修改 `pkg/pillar/evetpm/tpm.go`；207-tag ancestry 为 `1 ahead / 17 behind / 0 identical / 189 diverged`
- `CVE-2023-43632` 根 module 为 null，owner 为 `pkg/vtpm/build.yml`，但 pseudo patch 修改 `pkg/xen-tools/initrd/mount_disk.sh`；ancestry 为 `3 ahead / 14 behind / 1 identical / 189 diverged`
- 两行均失败 root-module、API-component、ancestry-total 与 patched-anchor gates，第二行另失败 pseudo-component-path coherence；均保持 `uncertain`，不计算 set relation，family status 为 `no_go_lf_edge_eve_release_graph_unstable`
- focused unit tests `12/12`；cache-only independent verifier 在权威远端与本地镜像均返回 `0`，确认同一 hash-bound cache 为 `0/2 projectable` 与 `label_is_human=false`
- analysis、summary、manifest SHA-256 分别为 `6fd97f25afce5a07aa9bd305bb761a8f461e9321b1204d91ff1f707d3e5e55e0`、`42e43fa76be905aa97cf09d15c245da318415523b8c6575e470ceeb87d44c897`、`764820ef22583cabbd737075bff99342d95c075041260a6a258f9016e0e2bb47`
- 权威远端 RQ2 全目录更新为 `226/226`
- 已更新 COSE setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`；原始 `wc -w=20,156`，SHA-256 为 `739f0f330174c102e46366860bd81afd0ab40271dcb275b6758181146effc082`
- package validator 共运行 `107` 项检查，新增 EVE claim-boundary/citation checks 通过；失败项仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- Mattermost 与 EVE 两个 repeated project families 均为 `0/2`，但失败边不同：Mattermost 已有 current module identity，缺 branch/legacy total mapping；EVE 连 structured repository coordinate 的 root-module identity、API/UI component semantics 和 branch ancestry 都不完整
- commit pack 证明可以在不依赖 compare API rate limit 的情况下冻结并重算大规模 ancestry；它解决的是可复现性和调用上限，不会自动解决 component identity 或 branch divergence
- 未新增 affected_versions candidate；combined candidate 仍为 `1,219/1,250=0.9752`，remaining unresolved 仍为 affected_versions `28`、cwe_ids `2`、references `1`

未验证：

- v1 protocol discovery 已观察 EVE tag/component structure，不能估计 project-family success probability，也不能升级任何 row candidate
- repository advisory UI 的 product/LTS ranges 与 public advisory API 的 historical pseudo record 可能反映 interface 或时间差异；本轮没有证明任一接口错误，也没有证明 NVD 或 GHSA 哪一方正确
- Codex 与 cache-only verifier 都不是现实人员；`label_is_human=false`，现实双人复核和 author signoff 仍为 0

下一步：

- 是否继续第三顺位 Hutool，应以能否预先冻结 Maven product/artifact total mapping 为条件；不能因为前两族 no-go 而降低门槛
- EVE 两行交现实人员明确选择 snapshot/API、repository-advisory product release、module commit 或 temporal/backport construct；不同 interface 不得互相覆盖
- 继续完成 2 条 CWE、1 条 references 与 28 条 affected_versions 的现实双人复核和 author signoff

### 17. 已完成并在权威远端验证：Hutool 209-release Maven graph mechanism pass v1

本次完成：

- 按 28-row edge audit 的冻结第三顺位读取 `CVE-2023-3276` 与 `CVE-2023-42276`；sample ID、NVD product claim、GHSA Maven components 与 Hutool rank `3` / score `8` 均由 sealed worklist、manifest 和 parent audit 绑定
- v1 前只读 protocol discovery 已观察 `hutool-all`、`hutool-core`、`hutool-json` 三个 Maven catalogs 相等，以及 `5.8.19`、`5.8.21`、`5.8.22` 的 aggregate POM/JAR 结构；合同显式记录 `protocol_discovery_disclosed=true` 与 `candidate_promotion_allowed=false`
- 固定 snapshot-extensional release domain：三个 catalog 的稳定三段式版本交集；排除 `5.8.0.M1` 至 `M4` 及 `5.8.4.M1` 五个 milestone tokens
- 把 total release-token correspondence 与 critical-anchor containment 分开：catalog equality 约束整个稳定域，source aggregate POM 与 published aggregate JAR 只在三个关键 anchors 上绑定 same-version core/json dependency、shade goal 和 compiled class contents
- 新增 cache-only verifier，不调用网络，独立复算 sealed inputs、18 个缓存文件 provenance、XML/ZIP 结构、release domain、两条集合关系、candidate boundary 与 advancement gate

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/affected_versions_hutool_maven_release_graph_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_hutool_maven_release_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_hutool_maven_release_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/hutool_maven_release_graph_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/hutool_maven_release_graph_v1/`

验证：

- 权威环境确认为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）
- 三个 Maven catalogs 均为 `214` tokens、`209` stable numeric tokens，稳定域从 `4.0.0` 至 `5.8.47`；五个 milestone exclusions 精确一致
- 三个 aggregate JAR 分别包含 `1743/1744/1745` 个 entries、`835/835/836` 个 core classes 和固定 `30` 个 JSON classes；三个 source POM 的 parent/version、core/json dependency 与 shade goal gates 全部通过
- `CVE-2023-3276` 的 NVD product set 为 `181`，GHSA core set 为 `209`；`CVE-2023-42276` 的 NVD singleton set 为 `1`，GHSA core/json union 为 `209`。两条均为 `nvd_subset_of_ghsa`，Codex development candidate 均为 `incomplete`
- family mechanism gate 为 `2/2`，状态 `mechanism_pass_requires_new_blind_cohort`；两条 `promoted_candidate` 均为 null，combined non-human candidate 保持 `1,219/1,250=0.9752`
- focused tests `11/11`，权威远端 RQ2 全目录更新为 `237/237`；cache-only verifier 在权威远端与本地镜像均返回 `0`
- analysis、summary、manifest SHA-256 分别为 `ceb10913394e7ec3a0d17fbb33dd58f63ab2ddd167b915f9d330e72c15f7a1e6`、`c8c2d6631be2c4b0fee28d149e6fe377e637889a8682acc506bebd5ae4d1123f`、`73280853a3fdfd563069491a0bea5795c61708afa282fdb9d3288b0ddeeb9a92`
- 已更新实验 README、COSE setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`；原始 `wc -w=20,756`，SHA-256 为 `7c056a14dc65c19e42c956c3b8b2914d52f6a0272ee2a30ad561bc3293ca17a3`
- package validator 共运行 `107` 项检查，claim-boundary/citation checks 通过；失败项仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- 第三个 repeated project family 首次得到可执行的 2/2 product/component mechanism projection；它说明 current Maven snapshot 中 aggregate/core/json release tokens 可同域比较，并且关键 boundary/witness anchors 有实际 component containment
- 两条 NVD set 均严格小于 GHSA union，因此在所声明的 extensional contract 下生成两条可追溯 `incomplete` development candidates
- 本轮没有新增 combined candidate 或 coverage；已揭封 discovery 使这两条只能用于机制说明和新 cohort 设计，不能回填 D/E unresolved、不能称纠错、准确率或 human gold

未验证：

- source POM/JAR containment 只检查三个 critical anchors，没有逐一检查 209 个历史 aggregate JAR；catalog equality 不能替代全版本 binary containment
- 当前 Maven Central 快照不一定等于 advisory 发布时的历史 release universe；`introduced=0` 且无上界的 intensional/temporal 含义尚未由现实人员批准
- Codex candidate 与 verifier 都不是现实人员；`label_is_human=false`，全项目现实双人复核与 author signoff 仍为 0

下一步：

- 不再在这两条已揭封 Hutool 行上改合同或 promotion；机制复用先使用冻结 v1 建立 label-independent、CVE-exposure-disjoint cohort，确认性结论则必须等待后续独立快照
- 现实人员对 Hutool 两行明确选择 snapshot-extensional、written-interval/intensional 或 historical-temporal construct，并完成独立复核与作者签署
- 继续完成 2 条 CWE、1 条 references 与全部 28 条 affected_versions 的现实双人复核和 author signoff

### 18. 已完成并在权威远端验证：Hutool 冻结机制的 6-row 同快照外部应用

本次完成：

- 在冻结 Hutool Maven v1 机制后，重新扫描权威 aligned corpus 的 `8,066` 个匹配对；Hutool family 共 `10` 条，先按 prior calibration、holdout、impact 与 mechanism artifacts 的并集排除 `1,967` 个已暴露 CVE，再保留 6 条 CVE-exposure-disjoint 记录
- exclusion parser 从 prior source artifacts 只投影 `cve_id`；selection logic 不访问 baseline、reviewer、consensus 或 candidate 字段，按预声明 route 保留 2 条 `product_to_aggregate_direct` 与 4 条 `product_via_aggregate_component`，并在 candidate computation 前封存 cohort
- 六条为 `CVE-2023-24162`、`CVE-2023-24163`、`CVE-2023-33695`、`CVE-2023-42277`、`CVE-2023-42278`、`CVE-2023-51075`；冻结 v1 的 209-release domain、catalog correspondence 与 anchor evidence 原样复用，没有按结果修改门槛
- availability 和 route structure 来自同一 aligned snapshot 且在 seal 前已观察，因此 manifest 显式记录 `same_snapshot_retrospective=true`、`availability_discovery_disclosed=true`、`candidate_promotion_allowed=false`、`label_is_human=false`
- 新增独立 verifier：重新扫描完整 aligned JSONL、复算 `1,967`-CVE 排除并集、六行 cohort、全部版本集合与 no-promotion gate；不把 analyzer 输出当作验证输入

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/affected_versions_hutool_external_application_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_hutool_maven_external_application.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_hutool_maven_external_application.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_hutool_maven_external_application.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/hutool_maven_external_application_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/hutool_maven_external_application_v1/`

验证：

- 权威环境确认为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）；cohort 为 `6` 行，route counts 为 `2/4`，封存 manifest 与 cohort SHA-256 分别为 `7009bfe08b68c953c0d6c407ed0ee6f3e0e464b64e02f1ffd1d3403ebd3b03ae`、`f99304768abe9eb6ede3ae27072126e8e6d86e2393997e19bd8f60d6281a4d1e`
- 六条均通过冻结 projection gate。`CVE-2023-24163` 为 `182/182` equal，生成 Codex development `representation_discrepancy`；其余五条 NVD/GHSA set sizes 为 `1/209`、`179/180`、`1/209`、`1/183`、`1/185`，均为 `nvd_subset_of_ghsa` 并生成 development `incomplete`
- candidate counts 为 INC `5`、RD `1`，状态 `retrospective_external_application_supported_nonhuman_only`；六条 promoted candidate 均为空，combined non-human candidate 保持 `1,219/1,250=0.9752`
- focused builder/analyzer/verifier tests 在本地与权威远端均为 `10/10`；权威远端 RQ2 全目录为 `247/247`；独立 verifier 在权威远端与本地镜像均返回 `0`
- 最终自查确认部分 prior source JSONL 自身含 `baseline_status` 字段；代码只投影 `cve_id`，相关文档已从“未读取标签文件”收紧为“标签字段不参与 selection”，不声称文件级不可见。合同哈希变化后旧 result manifest 被 verifier 正确拒绝；权威远端重建 provenance 后 analysis/summary 字节不变，仅 manifest 更新合同哈希，再次独立验证通过
- analysis、summary、result manifest SHA-256 分别为 `fb47025720d98bf77c653d60bb40307bfafc00b0ab52278dd0ff2825c017d543`、`a3bcdc7ce5e88ec3be60d0a0afa332824f37e6863038b22ae519a8f8f4e59cad`、`6bf3cbd60492a115c3fd333cc98a9a5db5d7f7e11fb310dcdfc7e84f76fa4886`
- 已更新实验 README、总计划、COSE setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`；原始 `wc -w=21,200`，SHA-256 为 `91d4f42bc2640352c48bf3e2033aec63b813a1c1051faa97bf3c6f30ed669ab8`
- package validator 共 `107` 项，`104` 项通过；失败仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- 冻结机制不只在原两条开发行可执行，也能在六条 CVE-exposure-disjoint Hutool 行上复用；结果同时包含 strict-subset 和 equal relation，说明合同不会把所有 eligible row 机械判成 `incomplete`
- 这增加的是 same-snapshot retrospective mechanism evidence，不是新 blind/time holdout，也不是 accuracy、human agreement 或 coverage gain；所有候选保持非人工且不晋升
- 两个 agent 的前序对比用于安排 Mattermost、EVE、Hutool 三条实验路线，最终队列与本轮结论均由可重算的 label-independent builder/verifier 决定，不以 agent 投票作为证据

未验证：

- 当前结果没有跨时间或独立数据快照；CVE exposure disjoint 不能替代 future-snapshot independence
- v1 仍只在三个 critical anchors 检查 source POM/JAR containment，没有逐一检查全部 209 个历史 aggregate JAR；现实人员也尚未批准 extensional、intensional 或 temporal range construct
- Codex development candidates 和独立程序 verifier 都不是现实人员；`label_is_human=false`，双人复核与 author signoff 仍为 0

下一步：

- 不再从当前 `8,066` 条 aligned snapshot 抽取 Hutool “新 cohort”；下一次确认实验只使用后续独立快照，并原样执行当前冻结机制
- 现实人员先批准 affected_versions range construct，再对全量 1,250 行包完成两位不同 reviewer 与 author signoff
- 继续完成 2 条 CWE、1 条 references 与全部 28 条 affected_versions 的现实双人复核；没有签收前不改变 production baseline 或论文性能结论

### 19. 已完成并在权威远端验证：剩余 2 条 CWE 与 1 条 references 的定向证据审计

本次完成：

- 从 D/E 揭封后仍未决的 37-row evidence-secondary 子集中固定三条非 `affected_versions` 记录：`CVE-2024-8020/cwe_ids`、`CVE-2023-4304/cwe_ids`、`CVE-2023-32187/references`
- 先封存三行 worklist、证据合同和完整官方响应，再运行 Codex expert-candidate analyzer 与独立 cache-only verifier；共冻结 `12` 个官方响应、`24` 个 body/metadata 文件，合计 `974,302` bytes，cache inventory SHA-256 为 `2c727e3e59490074395f23b81011d1b67fc4998e46e7962f4f2187ba2d3c11bd`
- contract 与 manifest 显式记录 `post_unsealing_targeted_diagnostic=true`、`protocol_discovery_disclosed=true`、`selection_uses_prior_unresolved_status=true`、`candidate_promotion_allowed=false`、`eligible_for_human_gold_claim=false`、`label_is_human=false`
- verifier 首次运行发现 analyzer 对 CWE 页面可见文本的标点/空白归一化与独立重算不一致；随后统一为 HTML visible-text 解析并增加回归测试，同时把 Froxlor、K3s 证据门禁改为缺失即拒绝，没有放宽任何结论门槛

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_residual_nonaffected_evidence_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_residual_nonaffected_evidence.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_rq2_residual_nonaffected_evidence.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_residual_nonaffected_evidence.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/tiebreak_v1/residual_nonaffected_evidence_v1/`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/residual_nonaffected_evidence_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/tiebreak_v1/evidence_secondary_v1/residual_nonaffected_evidence_v1/`

验证：

- 权威环境确认为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）；worklist 与 sealed manifest SHA-256 分别为 `715dc955c4314d4701b691bd15724f20cf0d95f4bc77b9710aa1dfa8fd50770d`、`8790ca9f3980327d1ea63310c72122ac63590a3fce3582db277791319e9f7226`
- `CVE-2024-8020` 的冻结源码证明 `post_state` 直接索引请求体 `state` 且本地无异常捕获；结合 CWE 定义，形成 1 条 Codex development `factual_conflict` candidate，但只支持具体的 uncaught-exception mechanism，不证明资源消耗描述在所有执行路径都不成立
- `CVE-2023-4304` 仍为 `uncertain`：冻结补丁支持缺失管理员姓名/邮箱校验，但 CWE-840 是禁止映射到真实漏洞的 Category，现有证据不足以在 CWE-284/CWE-862 等具体授权语义间作有效映射
- `CVE-2023-32187` 仍为 `uncertain`：按精确 frozen HTTP identity，NVD/GHSA reference 集合为 overlap non-subset；按窄化的 Bugzilla lookup suffix 修复，则 NVD 为严格子集。分类依赖尚未由现实人员批准的 resource identity construct
- 汇总为 `factual_conflict=1`、`uncertain=2`、mechanism-supported `1/3`、construct-unresolved `2/3`、promoted `0/3`，状态 `targeted_residual_diagnostic_no_promotion`；combined non-human candidate 保持 `1,219/1,250=0.9752`，现实人工签收保持 `0`
- analysis、summary、result manifest SHA-256 分别为 `5c1e2782a367eb976e823d25e3258534b8bcb592af6d538431bb307e002f86c9`、`b0141805c46158adc55f1e662437bd31e78fc42333997d4575f2486584700f24`、`2ea523c51b3e9ea61619ca3c9a0fb75f714338572f79235da35e28ed82948345`
- builder/analyzer/verifier 聚焦测试在本地与权威远端均为 `13/13`；独立 verifier 在两端均返回成功；权威远端 RQ2 全目录更新为 `260/260`
- 已更新实验 README、总计划、COSE setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`；原始 `wc -w=21,780`，SHA-256 为 `1f143ec544bb39161809577c9532439ab97a4df1da0664beab90817c159df589`
- package validator 共 `107` 项，`104` 项通过；失败仍仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- 这次审计把三条“缺少证据”的笼统未决拆成一条 source-local mechanism support 和两条 construct ambiguity，明确了现实人员需要裁决的最小问题
- `1/3` 是已揭封困难样本上的非人工定向诊断，不是盲测成功率、coverage gain、accuracy 或 human gold；三条均不进入 combined candidate

未验证与下一步：

- 现实 annotator 和独立 reviewer 仍需分别选择 CVE-2024-8020 与 CVE-2023-4304 的 valid concrete CWE，并对 CVE-2023-32187 明确 underlying content resource、frozen HTTP resource 或其他预注册 identity 口径，最后由作者签署
- 停止在这三条已揭封行上继续调合同或增加同模型投票；下一阶段优先完成全量 CWE 17 行、references 56 行和 typing 1,250 行现实双人复核

### 20. 已完成并在权威远端验证：RQ2 staged adjudication frontier 与 B 请求 provenance 缺口账本

本次完成：

- 对既有 A/B、C、D/E 请求日志和 sealed merge summaries 做后验只读审计；不修改旧日志、不改标签，也不补造缺失 response-error、rejected JSON、error reason 或 token usage
- 固定 exact payload identity 为有序 `sample_id` tuple；逐 payload 重算 request/success multiplicity、excess attempts、request row-attempts、successful reviewer-row decisions、retry overhead 和成功响应中实际记录的 token usage
- 将阶段收益统一重算为 A/B strict、C tiebreak 和 D/E evidence-secondary 三个累积节点；固定 combined coverage 门槛仍为 `0.982=1,228/1,250`，不在观察结果后放宽
- 合同预先规定 stop rule：C 与 D/E advancement gate 都失败、combined coverage 低于门槛且 residual audit 晋升为 0 时，停止在当前已揭封 cohort 上继续同模型升级

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_staged_adjudication_frontier_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_rq2_staged_adjudication_frontier.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_staged_adjudication_frontier.py`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/staged_adjudication_frontier_v1/analysis.json`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/staged_adjudication_frontier_v1/summary.md`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_typing_v1/staged_adjudication_frontier_v1/manifest.json`

验证：

- 权威环境确认为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）；聚焦 analyzer/verifier tests 为 `6/6`，独立 verifier 返回 `Verified staged frontier: 1219/1250; 3 unpaired request attempts; stop no-go`
- 权威远端 RQ2 全目录更新为 `266/266`
- A-E 共 `111` 个 request events、`108` 个 response-success events；request row-attempts 为 `2,767`，successful reviewer-row decisions 为 `2,677`，retry row overhead 为 `90`
- 三个 excess attempts 均来自 reviewer B。两个原大 payload 后续由 split retries 覆盖，另一个 payload 有 2 次完全相同 request 和 1 次 success，因此具体哪次失败不可判定；全部涉及行最终均有成功输出，但三次错误原因仍未知
- 成功响应实际记录的 usage 为 input `4,349,745`、cached input `1,106,432`、output `484,409`、reasoning output `54,319` tokens；这不包含三次缺失尝试，不能当作完整成本
- A/B 以 `2,500` 个成功 reviewer-row decisions 形成 `1,147` 条 strict candidates；C 以 `103` 个 decisions 新增 `66` 条，selected-row yield `0.6408`；D/E 以 `74` 个 decisions 新增 `6` 条，selected-row yield `0.1622`、per-reviewer-row yield `0.0811`
- 最终仍为 `1,219/1,250=0.9752`，距固定 `1,228` 行门槛差 `9` 行；未决为 affected_versions `28`、cwe_ids `2`、references `1`
- stop rule 通过，状态 `stop_same_model_escalation_no_go`；现实人员 review queue 仍为完整 `1,250` 行
- contract、analysis、summary、manifest SHA-256 分别为 `7505b2b7effc7a1f8135661337688c84ad5a919308b2731652c0e784ee880152`、`cd19908d13e1a09a4385391f921a3f44a0a587598f3efb637de06c5bd95f6846`、`4ce7b8222562c692e0899e4bac7b24ee44ce1ed1164c764ca1269c28f31c57af`、`ed867ea7446d7e0170619bc3c581cec55029e90b0a8dd98816c6cb5a54e93381`
- 已更新实验 README、总计划、COSE setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`；原始 `wc -w=22,265`，SHA-256 为 `f342603103df9c0019ac9a6cf1eb04dc1022dcfcdf9ca6087d70b9ae4e679e6b`
- package validator 仍为 `107` 项中 `104` 项通过；失败仅为既有 ImageMagick `convert` 缺失、latexmk prior-error state 与 LaTeX fatal/emergency-stop log，新增 frontier/provenance claim-boundary checks 未引入失败

当前效果：

- 总计划中“修复 B 的 3 个被拒绝批次 provenance 日志缺口”已收敛为可重算的 missingness ledger：行级结果完整，但 attempt 级错误 provenance 不完整；不通过伪造旧事件来制造表面完整性
- 当前证据支持停止继续追加同模型 reviewer：后续同类调用不能在已揭封 cohort 上产生确认性证据，且最近阶段的边际候选收益明显下降

未验证与下一步：

- C 的 `66/103` 与 D/E 的 `6/37` 条件于不同难度的逐级 selected sets，不是受控准确率或成本效果比较，也不能预测现实人员、其他模型或未来快照的 yield
- 继续价值最高的路径是现实 annotator + 不同现实 reviewer + author signoff，或从后续独立快照执行已冻结机制；不再为当前 1,250 行增加同模型 F/G reviewer

### 21. 已完成并在权威远端验证：RQ2 post-profile snapshot-external 双 Agent 比较

本次完成：

- 在权威环境 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）上从 NVD 官方 2026 CVE 2.0 feed 与 GitHub Advisory Database `main` 的固定 commit `95e6ff620d5494b93ba2234edfcf6a45187dc0a8` 采集隔离快照；保留下载 headers、原始归档、commit binding、规范化记录、对齐结果和哈希清单，不覆盖既有 2023--2025 主语料
- 在任何新 Codex 标签前分别冻结 acquisition contract 与 cohort contract。资格优先检查 profile seal 后 NVD/GHSA 双边 publication time；该 strict event-time 层为空，因此按预注册 availability rule 转入明确命名的 `snapshot_external` development 层
- 从 5,948 个旧对齐语料外的 `CVE-2026-*` 单 GHSA 记录中，按当前 status 的 70% proportional + 30% equal-audit strata、固定 SHA-256 seed 和跨字段全局 CVE 唯一约束，密封 5 字段各 50 条、共 250 条 blind cohort；六列 current/candidate profile prediction 在 reviewer 输出前密封，selection 不读取 candidate prediction
- 启动两个逆序隔离 Codex CLI reviewer roles。A 完成 `250/250`；B 在 `30/250` 后有一批因 affected_versions 缺少显式 reasoning type 被 strict validator 拒绝，随后保持同一密封工作表和 pass ID 断点补齐，最终完成 `250/250`。失败请求不产生 candidate row，并在最终 request audit 中保留为 1 个 unanswered validation attempt
- 新增 fail-closed merge、profile evaluator 与独立 results verifier，重新核对全部源/输出哈希、请求覆盖、A/B session 互斥、non-human 边界、strict consensus、六个 profile 指标、paired difference 和 CVE-cluster bootstrap

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_post_profile_time_cohort_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_post_profile_snapshot_cohort_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_post_profile_snapshot.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_post_profile_snapshot.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_post_profile_cohort.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_post_profile_cohort.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_rq2_post_profile_reviews.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/evaluate_rq2_post_profile_snapshot.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_post_profile_snapshot_results.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_post_profile_snapshot_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_post_profile_snapshot_v1/acquisition/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_post_profile_snapshot_v1/review/`

验证：

- acquisition independent verifier 重算为：strict event-time `0`、snapshot-external `5,948`、next tier `snapshot_external`；NVD 与 GHSA 的 normalized published time 均没有晚于 `2026-07-18T17:22:22.399430+00:00` profile seal 的记录，因此 `strict_event_time_claim_allowed=false`
- cohort independent verifier 重现 `250` 条 globally unique CVEs、每字段 `50` 条、固定 strata/顺序/raw projection 和六列 prediction；自然样本中仅 3 条 CWE predictions 与 current 不同，references original/audited profiles 均为 `0` 条差异
- A/B exact label agreement 为 `236/250=0.9440`，Cohen's kappa `0.9250`；strict consensus 为 `231/250=0.9240`。逐字段 strict 为 affected_versions `38/50`、cwe_ids `47/50`、published `50/50`、references `48/50`、severity `48/50`
- A 为 `50 request / 50 success / 250 rows / 50 sessions`；B 为 `55 request / 54 success / 250 rows / 54 sessions`，保留 1 个 unanswered validation attempt。A/B session ID 集合互斥；成功响应 usage 分别为 input `890,117/945,401`、cached input `548,608/593,152`、output `65,653/64,226`
- current 对 selective strict Codex consensus 为 `185/231=0.8009`，macro-F1 `0.7926`、full-cohort lower-bound agreement `0.7400`、reweighted strict agreement `0.8082`。CWE/combined candidates 为 `186/231=0.8052`，macro-F1 `0.7998`、lower bound `0.7440`、reweighted `0.8092`
- 三条差异为 `CVE-2026-49834`、`CVE-2026-28394`、`CVE-2026-54771`，均是 current `factual_conflict` 对 CWE candidate `representation_discrepancy`。仅 `CVE-2026-28394` 形成 strict consensus 并支持 candidate；另外两条均非 strict，paired descriptive difference 因此只有 `+1` 条，不能作为方法增益
- 新链路聚焦测试在本地与权威远端均为 `21/21`，权威远端 RQ2 全目录为 `287/287`；results verifier 返回 `Verified post-profile results: rows=250 strict=231 differences=3`
- acquisition analysis/manifest、cohort manifest、reviewer A/B、merge manifest、evaluation manifest SHA-256 分别为 `8e744436...d1d0e62`、`1a833ed8...9665`、`3e2dfd05...1acc2`、`f7183f4a...af95`、`29590fd0...f66`、`b389f386...72d5`、`8afc67b8...27f1`
- 已更新总计划与 COSE setup/results/discussion/threats/conclusion，并在权威远端重建 `paper/cose/full_draft.md`：原始 `wc -w=22,769`，SHA-256 `abc1da35fcff8f94731154d7e3204bd381fd18443f7e8fb9e93f8e66a73acb7e`。`--skip-latex-build` package validator 为 `104/106` checks 通过，新增 claim-boundary lint 已通过；两项失败仍为缺少 ImageMagick `convert` 与既有 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- 新采集解决了旧 1,250-row cohort 中 candidate predictions 完全相同、比较不可识别的问题，但只产生 3 条自然 profile 差异，且 strict paired evidence 只有 1 条；production default 保持不变
- 结果支持 snapshot-external development stability、双 Codex 一致性、请求 provenance 和一个 CWE candidate-direction case，不支持 post-profile event-time generalization、confirmatory method gain、human-gold accuracy 或 production switch

未验证与下一步：

- A/B 仍为同一模型、prompt 和配置下的两个隔离 pass，不是两位现实人员或独立模型家族；全部 `label_is_human=false`
- 真正 strict event-time cohort 仍为 0。后续只有在 NVD 与 reviewed GHSA 两边 published time 都晚于冻结点时，才能重新执行预注册时间层；不得把本次“采集发生在 seal 后”混同为“事件发生在 seal 后”
- 现实 annotator、不同现实 reviewer 和 author signoff 仍是投稿硬门禁；三条 CWE 差异应进入人工优先队列，但不能据 1 条 strict 支持批量切换 taxonomy profile

### 22. 已完成并在权威远端验证：post-profile 三条 CWE 差异的冻结证据双审

本次完成：

- 在权威环境 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj` 中核对 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`，只选择已揭封 250 行主评估中 current 与 CWE candidate 不同的 3 条记录；选择规则、9 个来源 URL、证据响应、原主评估绑定、prompt、代码和输出合同均写入密封清单
- 启动两个新的逆序隔离 Codex reviewer sessions；盲 worklist 不包含 current/candidate prediction 或原 A/B 标签，一个 pass 先判断 CWE 关系，另一个先判断具体漏洞机制
- v1 因 reviewer C 输出 `uncertain` 但 confidence 为 `medium` 被 merge fail-closed 拒绝；v2 明确该条件后，又因 reviewer C 输出的 CWE path 分隔符不满足 literal contract 被拒绝。两轮均未合并任何标签，原文件按精确字节归档。v3 在每行显式提供允许的 CWE path 字符串，并由 runner 在落盘前拒绝非法值
- 另启动两个只读 Agent 独立比较实验进展、论文贡献与未完成项。两者和本次主审判断一致：最稳的贡献是任务定义、五分类 taxonomy、证据化/预密封/fail-closed 协议与负结果；现有证据不足以把 CWE candidate 或 affected_versions 方法写成已验证增益

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_post_profile_cwe_evidence_secondary_contract_v3.md`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_post_profile_cwe_evidence_secondary_review_v3.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_post_profile_cwe_evidence_secondary.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/run_rq2_post_profile_cwe_evidence_review.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_rq2_post_profile_cwe_evidence_secondary.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_post_profile_cwe_evidence_secondary.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_post_profile_snapshot_v1/cwe_evidence_secondary_v3/`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/post_profile_cwe_evidence_secondary_v3/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_post_profile_snapshot_v1/review/cwe_evidence_secondary_v3/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_post_profile_snapshot_v1/cwe_evidence_secondary_v1_failed_contract_attempt.tar.gz`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_post_profile_snapshot_v1/cwe_evidence_secondary_v2_failed_path_contract_attempt.tar.gz`

验证：

- 9/9 个选定 URL 均成功冻结；reviewer C/D session 与 run ID 互斥。v3 merge 为 strict `3/3`、candidate direction `3`、current direction `0`、unresolved `0`，四个严格组件 relation/label/taxonomy support/specific mechanism 均为 `3/3` exact agreement
- `CVE-2026-49834` 的 CWE-347/CWE-345、`CVE-2026-28394` 的 CWE-770/CWE-400、`CVE-2026-54771` 的 CWE-75/CWE-74 均由两位 reviewer 判为 `representation_discrepancy`；原来 2 条 non-strict 行均被定向证据诊断解决
- 独立 verifier 返回 `Verified post-profile CWE evidence-secondary result: rows=3 strict=3 candidate=3 current=0 unresolved=0`
- v1/v2 失败归档 SHA-256 分别为 `ea3f89daadc80c834167fe36263b0147ea560d7f154bda4462e4fb163860c847`、`6cd6156c1f8c3ecdb99ddea321e63cd172c56569579597e30baec37fdf876de5`；v3 sealed manifest、reviewer C、reviewer D、summary、merge manifest SHA-256 分别为 `469342fc6a619eb53356edd132dc3976c637c061b88f92a9a79dde08bf52ee0f`、`dedbe7b7b2a72e9ccedcf86af363476557d0f3717f9b747f7e6e9e21a4d4b8fb`、`f6f0ddf764dacd21d5d67f30b7a6be7efebed0e26c7ff1b17a1b857a998ce100`、`658d4935b173d2d2d322e83d48fbc6d0614da8f1a9f7fac3d9e256935127393e`、`a567d1fda1fe9350cc24920fe832b600e54a097b114c85eb170d053d30a0fbe3`
- 聚焦 builder/merge tests 为 `7/7`，runner tests 为 `5/5`，权威远端 RQ2 全目录 tests 为 `299/299`
- 已更新总计划与 COSE setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`：原始 `wc -w=23,267`，SHA-256 `14dd45ae602f415f1dd7a94bd39b981a8f1b6433a92466c9037957f34452cd4d`。`--skip-latex-build` package validator 为 `104/106` checks 通过，新增 claim-boundary lint 通过；两项失败仍为缺少 ImageMagick `convert` 与既有 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- 冻结外部证据使三个已知 profile-difference 案例都得到一致的 candidate-direction 机制解释，说明 official taxonomy path 需要与具体漏洞机制一起判断，而不能只看集合是否不相交
- 密封 250 行主评估保持不变：current 仍为 `185/231`，CWE candidate 仍为 `186/231`，原 paired descriptive difference 仍只有 `+1`。`sealed_250_row_evaluation_changed=false`、`candidate_promotion_allowed=false`、`production_default_changed=false`

未验证与下一步：

- 这 3 条记录是在 A/B 和 profile difference 已揭封后选择的，同一模型家族的两个新 pass 不是现实人员、独立模型家族或 human gold；`3/3` 不能解释为无偏准确率、确认性方法增益或时间泛化
- v1/v2 的失败说明输出接口本身会影响可合并性；它们只作为失败 provenance，不纳入 v3 投票或结果
- 停止继续在这 3 条已揭封记录上增加同模型 reviewer。由现实 annotator、不同现实 reviewer 和作者签收这三条构念，再等待双源事件时间都晚于 profile seal 的后续 strict cohort

### 23. 已完成并在权威远端验证：post-profile CWE 全 50 条冻结证据双审

本次完成：

- 将三条已知 profile differences 隐藏到密封 250 行 cohort 的全部 50 条 `cwe_ids` 记录中，避免只给 reviewer 展示差异行；50 条由 33 个 exact set、9 个 literal strict subset、4 个 overlap non-subset 和 4 个 disjoint 组成
- 每行最多选择 NVD/GHSA 各自排序后的 3 个引用，共冻结 135 个 URL 响应；134 个成功、1 个 `url_error`。两个 blind worklist 分别采用原顺序和精确逆序，均不含 current/candidate prediction、原 A/B 标签、strict 状态或 profile-difference 标识
- V1 合同错误地强制所有 literal strict subset 为 `incomplete`，在 reviewer 输出与语义证据冲突时 fail closed；V2 修复语义后完成两份 50 行输出，但 merge 发现 literal quote 不是冻结正文子串。两轮均未生成合并结果，并按精确字节封存
- V3 将 rationale、citation schema、成功 URL membership、20--280 字符 literal quote、重复 citation 和允许 CWE path 全部前移到 runner 落盘前验证；E/F 各 10 个五行请求，使用 20 个互斥 ephemeral sessions，未产生 V3 rejected batch

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_post_profile_cwe_all50_evidence_contract_v3.md`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_post_profile_cwe_all50_evidence_review_v3.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_post_profile_cwe_all50_evidence.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/run_rq2_post_profile_cwe_all50_review.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_rq2_post_profile_cwe_all50.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_post_profile_cwe_all50.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_post_profile_snapshot_v1/cwe_all50_evidence_v3/`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/post_profile_cwe_all50_evidence_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_post_profile_snapshot_v1/review/cwe_all50_evidence_v3/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_post_profile_snapshot_v1/cwe_all50_evidence_v1_failed_fixed_subset_contract_attempt.tar.gz`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_post_profile_snapshot_v1/cwe_all50_evidence_v2_failed_literal_evidence_contract_attempt.tar.gz`

验证：

- V3 双审 strict 为 `49/50=0.98`；set relation exact `50/50`，discrepancy label、taxonomy compatibility 和 specific mapping verdict 均为 `49/50`
- strict 标签分布为 equivalent `33`、incomplete `8`、representation_discrepancy `6`、factual_conflict `2`；原 A/B strict 47 条中全部保持可判断，并额外解决原 3 条 non-strict 行
- 对 49 条 evidence strict rows，current 为 `45/49`，CWE candidate 为 `48/49`；三条 profile differences 均 strict 且全部支持 candidate direction。唯一 evidence 非 strict 行是 `CVE-2026-8149`，E/F 分别判为 `incomplete` 与 `factual_conflict`；唯一 profiles-equal 且两种规则都偏离 evidence consensus 的行是 `CVE-2026-24053`
- 独立 verifier 返回 `Verified post-profile CWE all-50 evidence result: rows=50 strict=49 current=45 candidate=48 difference_candidate=3`
- V1/V2 失败归档 SHA-256 分别为 `ce38009a9e986eadbd381cf560d75dc8346b5719379dbaf5bde394527fe92ea1`、`6b6cc2610e6e1b9b75ccc10cbd476533d94f8977d95c4a69d59cc5e4954b779b`
- V3 sealed manifest、reviewer E、reviewer F、summary、merge manifest SHA-256 分别为 `17628da54ead1dfa598d97fdd4093e492873848088d79aa4a325f32706dd4a93`、`3d903174a73b9d9c92868b945210c4a48839642c0052dd15957f2ed040ad2c0f`、`3ac6d5c70df7005f6b2ef9eec0d18282b523f988f422246180aa5093fc462251`、`60812a932fde2d1508cfe7f4ea20abb1ec9a8ae1135cd586409cb77aa60ca02e`、`9b896846e96ddb8a6f9552a351153c3051b42c923c88b8fa9152dbf7e39482c8`
- V3 聚焦测试为 `13/13`；独立 verifier、输入哈希、session 互斥和 forbidden blind key 检查全部通过

当前效果：

- 覆盖全部 CWE 字段后，三条已知差异仍都得到 candidate-direction 解释，且不再由 reviewer 显式知道哪些行是 profile difference；这比只审三条的 case diagnostic 更能检查字段内 control 一致性
- 密封 250 行主评估不变：current `185/231`、CWE candidate `186/231`、paired descriptive difference `+1`。全字段 `45/49` 对 `48/49` 是解封后的独立诊断分母，不得替换主指标或触发 candidate promotion

未验证与下一步：

- 字段选择、证据合同和 V3 修订均发生在 A/B 与 profile 揭封后，E/F 仍属同一 Codex 模型家族；`+3/49` 不是确认性收益、human accuracy、时间泛化或 production evidence
- 由现实 annotator 和不同现实 reviewer 优先裁决 `CVE-2026-8149`、三条 profile differences 与 `CVE-2026-24053`，再完成全部 250 行三阶段签署

### 24. 已完成并在权威远端验证：post-profile 250 条现实人工三阶段盲包

本次完成：

- 将密封 cohort 全部 250 条记录投影为 source-bound 空白包，保留两源字段值、上下文和冻结引用；移除 baseline、sampling stratum、六列 profile prediction、A/B 与 E/F 输出、consensus、strict 状态和调度优先级
- 建立 annotator、不同 independent reviewer、author resolution/signoff 三阶段 schema；任何 packet/manifest 均固定 `label_is_human=false`、`eligible_for_human_gold_claim=false`
- 作者侧无标签调度器按 19 条原 A/B non-strict、3 条 post-hoc CWE diagnostic focus、44 条 baseline-vs-consensus mismatch 和 184 条全量补全排序；调度器不得交给 reviewer
- fail-closed validator 绑定主 cohort seal、prediction、A/B merge、all-50 evidence merge 和 scheduler 哈希，并拒绝来源漂移、pending 行夹带内容、同一 reviewer ID、未签署 resolution、快照外 URL 或 packet 自称 human gold

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_post_profile_human_review_packet.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/validate_rq2_post_profile_human_review.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_post_profile_snapshot_v1/human_review/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_post_profile_snapshot_v1/human_review/`

验证：

- 权威环境为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`，运行时核对为 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`；聚焦测试 `12/12`，三个 Python 文件均通过 `py_compile`
- 生成 250 条、每字段 50 条空白行；普通 validator 返回 0，`--require-signed` 与 `--require-complete` 在 0 signed 状态均返回 2
- readiness 为 `250 pending / 0 signed / 0 excluded / 0 validation errors`，`file_workflow_complete=false`、`human_gold_promotion_performed=false`
- blank packet SHA-256 为 `35d388d25c93201c52d0ef61344e35a78616e2b15ed635e8e36ccaa1f857e7d0`；scheduler SHA-256 为 `ae6095c7ae878a7c1fca9c3a52c07f0a34073371701891c693b4d545550750d7`
- 权威远端 RQ2 全目录测试更新为 `324/324`；已同步更新总计划与 COSE setup/results/discussion/threats/conclusion/submission readiness，并重建 `paper/cose/full_draft.md`：原始 `wc -w=23,979`，SHA-256 `595edd1b2e9926b703c2d03cbd4957afb558df1b59c4e9b07e20159fea63d97a`
- `validate_cose_package.py --skip-latex-build` 仍为 `104/106` checks 通过；新增 claim boundary 未引入失败。两项既有失败仍是缺少 ImageMagick `convert` 与 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- 新 cohort 的现实人工复核已有完整、可追踪且不会泄露非人工标签的执行入口；优先队列可先处理 22 条最关键行，但完成门禁仍要求全部 250 条 final 且无 exclusion

未验证与下一步：

- 当前仍没有任何现实人员决策或签署。validator 只能检查文件内 ID 与流程字段，不能证明 ID 对应真人或两位 reviewer 实际独立；身份与独立性必须线下核验
- 完成两位现实人员的独立标注和作者签署后，再运行 `--require-complete`，并在外部身份核验通过后单独决定是否生成 canonical human-gold artifact

### 25. 已完成并在权威远端验证：权威地址叙事与 RQ2 全量人工门禁审计

本次完成：

- 全仓扫描远端地址、用户路径和 `code-defender` 叙事；没有发现其他 IP，但旧进度记录中仍有只写主机名的条目。现已统一为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`，`code-defender` 只作为实际 `hostname` 核验值
- 扩展 COSE package validator，将旧 1,250 行 typing 人工包和新 250 行 post-profile 人工包加入独立 submission checks；验证 artifact type、总数、signed/excluded/pending 守恒、零 schema error、禁止 packet 自称 human gold，以及必须外部核验真人身份
- 新门禁只判断 file workflow 是否完整，不从 human ID 字符串推断真人身份；Codex 决策与空白 packet 均不能清除 blocker

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/plans/project_progress_log.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/paper_artifacts/validate_cose_package.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/paper_artifacts/test_validate_cose_package.py`

验证：

- 权威环境为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`，运行时核对 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`
- package human-gate 聚焦测试为 `3/3`，两个文件通过 `py_compile`
- `validate_cose_package.py --skip-latex-build` 更新为 `106/108` checks 通过；新增两项 RQ2 typing 人工 readiness checks 均通过，原两项 ImageMagick/LaTeX 执行失败不变
- manifest 明确记录 typing v1 `0/1,250 signed`、post-profile `0/250 signed`，并新增 blocker：两套全量现实人工签收未完成，完成文件后仍需外部身份与独立性核验

当前效果：

- 仓库叙事中的权威定位现在统一使用 IP，不再把主机别名当作地址；提交检查也不再遗漏两套最大 RQ2 人工工作流

未验证与下一步：

- 新检查不能代替真实身份核验；当前所有现实人员签署计数仍为 0
- 继续使用无需新标签的分析界定现有实验可达到的最大方法差异，不增加同模型 reviewer

### 26. 已完成并在权威远端验证：post-profile 无标签配对结果包络

本次完成：

- 在不读取 A/B、E/F、consensus、evidence-secondary 或 human label 的合同下，只绑定原 250 行 sealed source/prediction hashes，枚举 current 与 `cwe_taxonomy_v1` 三条差异行的全部五分类标签组合
- 每条差异在 candidate-only match、current-only match 和 both-wrong 时分别贡献 `+1/-1/0`；枚举计数明确禁止解释为标签概率、先验或经验频率
- 独立 verifier 不调用 analyzer，重新读取密封 prediction、重算差异行、125 种 assignment、paired delta 分布、逐字段上限和 claim boundary

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_post_profile_paired_outcome_envelope_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_rq2_post_profile_paired_outcome_envelope.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_post_profile_paired_outcome_envelope.py`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_post_profile_snapshot_v1/paired_outcome_envelope_v1/`

验证：

- 权威远端聚焦 analyzer/verifier tests 为 `4/4`，四个 Python 文件通过 `py_compile`
- 独立 verifier 返回 `Verified paired outcome envelope: rows=250 differences=3 assignments=125 max_abs_accuracy_delta=0.0120`
- 247/250 行预测完全相同；仅 3 条 CWE 差异可改变 paired sign。完整 cohort 上 candidate-current accuracy difference 的绝对值上限为 `3/250=0.012`，CWE 字段内上限为 `3/50=0.06`，其余四字段为 0
- 125 种逻辑组合的 paired delta `-3..3` 计数依次为 `1,9,30,45,30,9,1`；candidate better 40 种、current better 40 种、tie 45 种，不解释为概率
- analysis、summary、manifest SHA-256 分别为 `bac8a053cd2281eee00a4b1a0556b1f0d05eb4d94df38c7926b5330b9a1563ac`、`b57790bb7331baeb3dd0b89f1a1cce725b6400ff9daf1c5233a74652e932fdea`、`9e5b4f9d971eb0409d362b6a0a72a5e5341358a6495e0b648fb8daf897f017fc`
- 权威远端 RQ2 全目录测试更新为 `328/328`；package human-gate tests 为 `3/3`，远端地址叙事中 `code-defender` 未同时出现 `100.101.249.5` 的行数为 0
- 已更新总计划与 COSE setup/results/discussion/threats/conclusion/submission readiness，并在权威远端重建 `paper/cose/full_draft.md`：原始 `wc -w=24,439`，SHA-256 `7b12ec442b963823a771b72bf995a0995f032ac4dab4360eb66c66485cc84c11`
- `validate_cose_package.py --skip-latex-build` 为 `106/108` checks 通过；label-free claim-boundary lint 通过。两项失败仍仅为缺少 ImageMagick `convert` 与既有 LaTeX fatal/emergency-stop log，`submission_ready=false`

当前效果：

- 无论未来三条真人标签如何，本 cohort 上两种 profile 的总体准确率差都不可能超过 1.2 个百分点；因此现有样本即使补齐 human gold，也只能支持很小的 profile-level effect
- 三条差异的真人标签足以确定 paired sign，但不能给出绝对 accuracy、macro-F1、构念有效性或其余 247 行错误分布；这些仍要求完整 250 行现实双审与作者签署

未验证与下一步：

- 当前没有任何真人标签，包络不是 human-gold evaluation，也不支持 candidate promotion
- 后续确认性方法若需要更高检验力，必须在双源事件时间均晚于 seal 的新 cohort 中先确保足够的自然 prediction differences；不能事后只抽差异字段补充样本

### 27. 已完成并在权威远端验证：COSE LaTeX 可复现构建与完整 package 检查

本次完成：

- 在权威环境 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj` 核对 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`
- 为 `experiments/paper_artifacts/build_cose_latex.py` 增加确定性 SVG-to-PNG 后端选择：优先使用 ImageMagick `convert`，不可用时回退到 `CairoSVG==2.8.2`；依赖固定在 `experiments/paper_artifacts/requirements.txt`
- 在权威远端安装 CairoSVG 依赖，并通过 TinyTeX `tlmgr` 更新后安装 `elsarticle`；随后重新生成图件并完成干净的 `latexmk` 编译
- 按最新 80 页 PDF 重新渲染联系表，并目视检查整套页面缩略图；未观察到空白渲染、页面缺失或明显重叠

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/paper_artifacts/build_cose_latex.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/paper_artifacts/requirements.txt`
- `/home/xiaoyuliang/code/vuln-adj/experiments/paper_artifacts/test_build_cose_latex.py`
- `/home/xiaoyuliang/code/vuln-adj/paper/cose/latex/main.pdf`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/visual_checks/pdf_contact_sheet/main_contact_sheet.png`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_package_manifest.json`

验证：

- 构建器与 package 聚焦测试为 `5/5`
- 方法框架和 RQ1 热图分别成功生成 `1180x900` 与 `980x544` PNG；LaTeX PDF 为 80 页、556,853 bytes，SHA-256 为 `95b7f0360eac2d95e918b4ab1b090c1b738b0a730167eec7ca3fc6670973ab42`
- 最终 LaTeX 日志中的 undefined citation、fatal error 与 emergency stop 计数均为 0
- 完整运行 `validate_cose_package.py` 得到 `status=pass`、`109/109` checks 通过；联系表含 80 页且新于 PDF

当前效果：

- ImageMagick 缺失和旧 LaTeX fatal log 已不再是执行阻塞；论文包的可复现生成、编译和结构检查全部通过
- `submission_ready=false` 保持不变，因为 RQ2 现实人工签署为 typing `0/1,250`、post-profile `0/250`、references `0/56`、CWE `0/17`，RQ3 human final 为 severity `0/80`、affected_versions `0/100`，且投稿元数据/声明仍有占位符

未验证与下一步：

- 当前联系表只能用于全局版式扫描，不能替代作者对正文、长表和引用可读性的逐页终审；最新重建已在第 29 节刷新为 83 页
- 完成现实人工金标、作者信息与声明后，仍需按最终稿重新构建 PDF、刷新联系表并重跑完整 package validator

### 28. 已完成并在权威远端验证：post-profile 最终 16 条非 CWE 冻结证据双审与 no-go

本次完成：

- 在权威环境 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj` 核对 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`
- 重新核对 250 行主评审的 19 条 A/B 非严格行：3 条 `cwe_ids` 已由 all-50 CWE v3 审计严格解决；本阶段固定选择其余 16 条，字段为 affected_versions `12`、references `2`、severity `2`
- 在任何 G/H 输出前冻结选择器、合同、提示、相反输入顺序、执行后端和门槛；盲表不包含 baseline、六个 profile prediction、A/B 或 CWE reviewer 决策
- 只从原 NVD/GHSA reference context 选择并缓存最多六个 URL；16/16 行有成功非空证据，50 个缓存记录均为 `ok`
- 运行 G/H 两份逆序、session 隔离的 Codex 非人工审阅，各完成 `16/16`，每份使用 8 个 ephemeral sessions；所有输出保持 `label_is_human=false`
- 合并曾两次 fail closed：通用 session 审计先错误假定 CWE reviewer 使用 `sample_id`，随后错误假定 session 位于 reviewer JSONL。两次均未写结果；修复后从已绑定哈希的 CWE request log 读取 `session_id`，未修改密封 manifest、盲表、G/H 输出、提示或门槛

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_post_profile_unresolved_evidence_secondary_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_post_profile_unresolved_evidence_secondary.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_rq2_post_profile_unresolved_evidence_secondary.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_post_profile_unresolved_evidence_secondary.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_post_profile_snapshot_v1/unresolved_evidence_secondary_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_post_profile_snapshot_v1/review/unresolved_evidence_secondary_v1/`

验证：

- 聚焦测试为 `6/6`，RQ2 全目录测试为 `334/334`；新 Python 文件均通过 `py_compile`
- 独立 verifier 返回 `selected=16 strict=4 combined=238 remaining=12 gate=no_go_post_selected_non_human_evidence_secondary`
- G/H exact label agreement 为 `11/16`，证据合格 strict 为 `4/16=0.25`：affected_versions `2/12`、references `2/2`、severity `0/2`
- 四条 strict 为两个 references `representation_discrepancy`、一个 affected_versions `equivalent`、一个 affected_versions `incomplete`
- staged candidate 由 sealed A/B strict `231`、post-selected CWE strict additions `3` 和本阶段 strict additions `4` 组成，共 `238/250=0.952`，剩余 `12` 条未决
- 固定 evidence availability 与 staged coverage 门槛通过，secondary resolution `0.25<0.40` 失败，最终状态为 no-go
- sealed manifest、summary、result manifest SHA-256 分别为 `5feba16500e4b96b8d7e93f6a71dc9ec53d2894377dd22456e25ecd9166d0cb8`、`b3c3f32a960228f3c06a7adbb0a88dc9b9c71e4e62657acc802936e5ead80c2f`、`d585e6dbe2ab1734aa0d76e457fe1f539f507c76f2c9aab46d6a2a04e1463095`
- package validator 已加入 hash、boundary 和独立 verifier 三项检查；`--skip-latex-build` 为 `111/111` 通过，`submission_ready=false` 的五类现实阻塞不变
- 权威远端随后重建 `paper/cose/full_draft.md`，原始 `wc -w=25,005`，SHA-256 为 `fa759befac0f453307702d992da91b987ec8c22d99dae07feba5f1463fc9e2fe`；LaTeX 生成 82 页 PDF，并刷新 82 页联系表
- 完整运行 `validate_cose_package.py` 得到 `status=pass`、`112/112` checks 通过、`submission_ready=false`；包内一致性通过不改变现实人工签署、RQ3 audit 和投稿元数据阻塞

当前效果：

- 当前同模型证据升级已经覆盖 post-profile 原 19 条未决的全部字段：3 条进入 CWE field-complete 审计，其余 16 条进入本阶段；但最终仍有 12 条无法取得证据合格严格决定
- current 与 CWE/combined profiles 在 staged candidate 上分别为 `188/238` 与 `191/238`；新增四条非 CWE 行的所有 profile prediction 相同，因此 `+3` 完全继承自此前 CWE stage，不是本阶段带来的 profile 改进
- 50/50 fetch 成功而 resolution 只有 4/16，直接说明瓶颈是 CVSS、resource identity 和 product/package/range construct，而不是通用页面是否可抓取

未验证与下一步：

- staged candidate 是揭封后按难例逐级条件化的同模型候选，不是 human gold、accuracy、确认性方法增益或 temporal generalization；密封主评估 `185/231` 对 `186/231` 不变
- 不再对这 12 条增加同模型投票或放宽门槛；现实 annotator、不同现实 reviewer 和 author signoff 仍需完成全 250 行，优先处理这 12 条、三条 profile differences 和 CWE field-complete 的一条未决

### 29. 已完成并在权威远端验证：post-profile exact paired-test 可识别性与样本规划边界

本次完成：

- 重新扫描仓库叙事文件中的 IPv4；排除外部相关工作网页后只出现 `100.101.249.5`，共 33 处，没有其他项目远端 IP。权威执行定位继续固定为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`，`code-defender` 只作实际 hostname 核验
- 新增完全无标签的 paired-test identifiability 合同与分析器，只读取原 250 行密封 source/prediction 和 manifest，不读取 A-H、consensus、evidence-secondary 或人工标签
- 对六个 profile 的完整预测向量分组，并对全部 15 个 pair 计算条件 exact two-sided McNemar 的最小可达 p 值；对代表性的 current/CWE 跨组差异枚举全部 `5^3=125` 个标签组合
- 将理论显著性下限、条件 exact power 和基于观测 prediction-difference rate 的 future-cohort availability 分开输出；所有假设与非预注册边界写入合同、analysis 和 manifest
- package validator 新增输入输出 hash、固定结果边界和独立 verifier 三项 fail-closed checks

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_post_profile_paired_test_identifiability_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_rq2_post_profile_paired_test_identifiability.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_post_profile_paired_test_identifiability.py`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_post_profile_snapshot_v1/paired_test_identifiability_v1/`

验证：

- 权威环境核对为 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`
- 四个新 Python 文件通过 `py_compile`；聚焦测试 `7/7`，RQ2 全目录更新为 `341/341`
- package 测试首次以文件模块路径直接调用时因测试目录未进入 import path 而失败；改用既有 `unittest discover` 入口后 `5/5` 通过，不涉及代码或结果修改
- 独立 verifier 返回 `profiles=6 classes=2 differences=3 min_p=0.2500 rejecting_assignments=0/125`
- analysis 与 manifest SHA-256 分别为 `5bbb79f2020c73b6f81e2a396da508f1e6b15c2d14dfc62d89f680bb32dc954f`、`9c88da42f87679762333f29af32ddb5765ddf33a8e82e2a1a96cfeaf4e021f97`
- `validate_cose_package.py --skip-latex-build` 为 `114/114` 通过，`submission_ready=false` 的五类现实阻塞不变
- 更新 COSE setup/results/discussion/threats/conclusion/submission readiness 后，在权威远端重建 `paper/cose/full_draft.md`：原始 `wc -w=25,409`，SHA-256 为 `06c65deeb2ce11303ffdd08497196f2ad2e9bd4004d84e30c1b942c185ab6352`
- 干净 LaTeX 构建生成 83 页、563,042-byte PDF，SHA-256 为 `eadbb3955efccd5fd7305e291844390db3f076cf8e908c477355e261b0a040ff`；83 页联系表已刷新
- 完整 `validate_cose_package.py` 为 `115/115` 通过、`status=pass`、`submission_ready=false`；五类现实人工/投稿元数据 blocker 不变

当前效果：

- 六个 profile 只有两个预测向量等价类：`current` 与两个 references profiles 完全相同；`cwe_taxonomy_v1` 与两个 combined profiles 完全相同。任意跨类 pair 都只在相同 3 条 CWE 行上不同
- 125 个标签组合中，有效 correctness-discordant rows 为 0/1/2/3 的组合数分别为 `27/54/36/8`；exact p 为 `1.0/0.5/0.25` 的组合数分别为 `105/18/2`，`0/125` 能在 `alpha=0.05` 下拒绝
- 当前 cohort 的最小可达 p 值为 `0.25`；即使三条 gold 全部同向，也无法得到显著 paired result。双侧 exact 检验理论上至少需要 6 条全部同向的有效 correctness-discordant rows
- 在观测 prediction-difference rate `3/250=0.012` 保持稳定且独立抽样的假设下，6 条差异的期望样本量是 500；至少观察到 6 条差异的概率达到 0.80/0.90/0.95 时，对应 future cohort 为 `658/771/874` 行
- 条件于行已经是 correctness-discordant，若 candidate-direction 胜率假设为 0.70/0.80/0.90，则 exact test 达到 80% power 的最小有效行数为 `49/20/12`

未验证与下一步：

- 658/771/874 依赖稳态差异率与独立抽样，49/20/12 又依赖未知的真实方向胜率；这些数字不是预注册样本量、未来分布估计或方法增益
- 结果证明当前 cohort 在任何 gold 分配下都没有 paired-test capacity，但不证明 current 与 CWE 方法等价，也不提供 absolute accuracy、macro-F1 或 construct validity
- 后续 strict event-time cohort 在冻结前应先确定 human-approved outcome contract，再把 prediction differences、gold 后 correctness discordance 和目标 power 分开规划；当前 250 行 cohort 不再追加同模型审阅或重新抽样

### 30. 已完成并在权威远端验证：post-profile eligible-universe prediction census

本次完成：

- 在权威环境 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj` 核对 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`
- 新增 prediction-only census 合同、分析器与独立 verifier；只读取官方 acquisition、eligible universe、六个冻结 profile 和原 250 行 sealed predictions，不读取 A-H、consensus、evidence-secondary 或 human label
- 分析器必须先逐行精确回放原 250 行六列 prediction，随后才把同一 profile 代码扩展到全部 5,948 个 snapshot-external eligible CVE 的五个字段
- census 不重新抽样、不创建 reviewer worklist、不生成标签；独立 verifier 不导入 analyzer，重新构造 eligible universe、profile predictions、差异行、向量等价类和 sample replay
- package validator 新增结果 hash、固定边界和独立 verifier 三项 fail-closed checks

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_post_profile_eligible_universe_prediction_census_contract_v1.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_rq2_post_profile_eligible_universe_prediction_census.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/verify_rq2_post_profile_eligible_universe_prediction_census.py`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/rq2_post_profile_snapshot_v1/eligible_universe_prediction_census_v1/`

验证：

- 聚焦测试首次出现 2 个失败：synthetic references fixture 的 original/audited 变化落在同一 union row，测试错误预期为 3 行；在任何正式结果生成前把两个期望值从 3 修正为 2，随后聚焦测试 `7/7` 通过
- 新 Python 文件均通过 `py_compile`；RQ2 全目录测试为 `348/348`；package 聚焦测试为 `6/6`
- analyzer 返回 `cves=5948 instances=29740 difference_rows=34 difference_cves=34`；独立 verifier 返回相同结果
- `validate_cose_package.py --skip-latex-build` 为 `117/117` 通过、`status=pass`、`submission_ready=false`；五类现实人工/投稿元数据 blocker 不变
- analysis、difference JSONL、manifest SHA-256 分别为 `8f25c88dafbccf69a7d0083c6cb8fb2a228e3716a9c9b3398f41fb505749d18b`、`787289179479f1acc442549a3114f9160090c1eaff3c16f408c96f51fd586ce3`、`b24a8ef70129ebdbcffafe6970d60922b20e461d582eabc4f37a5c5ae5eb5869`
- 论文 claim-boundary 首次复跑按预期 fail closed：threats 段落使用 `performance` 时缺少同句非 gold guard，且 Markdown/LaTeX 尚未重建；补充“无概率控制层不能报告 absolute performance/prevalence”的限定后，claim lint 通过
- 权威远端重建 `paper/cose/full_draft.md`：原始 `wc -w=26,081`，SHA-256 为 `351480a22a27d81c02c3f4dd316dc9f65c194994894cef7e7d8180042815baeb`
- 干净 LaTeX 构建生成 85 页、567,698-byte PDF，SHA-256 为 `68bd128c578d30aa5c1fca0517c8b94fbf52b7e4ddb043150388130ca45cdde9`；final log 中 unresolved citation、fatal error、emergency stop 均为 0，并已刷新 85 页联系表
- 完整 `validate_cose_package.py` 为 `118/118` 通过、`status=pass`、`submission_ready=false`；五类现实人工/投稿元数据 blocker 不变

当前效果：

- 全量 `5,948×5=29,740` 字段实例的 union 只有 34 条差异，分别落在 34 个 CVE，multi-field difference CVE 为 0
- 相对 current，reference original/audited 为 `5/3` 条 references 差异，CWE 为 `29` 条 `cwe_ids` 差异，combined original/audited 为 `34/32` 条；完整 universe 上六个 profile 各自形成独立 prediction vector
- 原 250 行六列 prediction 精确回放；其中 references 差异仍为 0，CWE/combined 差异仍为 3。分层样本的 `3/250` 因此不能作为简单总体 prediction-difference rate，先前 658/771/874 的稳态率规划假设不适用于当前完整 eligible universe
- current 对 reference original/audited 在当前 universe 只有 5/3 个潜在差异 CVE，即使全部成为同向 correctness discordance，也分别只能达到理论最小 p=`0.0625/0.25`；CWE/combined 的 29/34/32 个 prediction differences 只提供条件容量，不代表有效 discordance 或 candidate wins

未验证与下一步：

- census 没有 reviewer 或 gold label，34 条 prediction differences 不是 accuracy、correctness、human-gold、confirmatory gain 或 production-switch 证据
- 当前 snapshot-external universe 已揭封且 strict event-time 为 0，不能把差异总量外推为未来 prevalence 或直接转成确认性 cohort
- 后续 strict event-time 设计应先对密封 profile 做 eligible-universe prediction census，再在标签前冻结分歧富集 paired comparison；若报告 absolute accuracy 或 prevalence，另保留概率抽样 control layer，并按 CVE 分组避免伪重复
- 现实人类签署和作者 signoff 仍是主阻塞；本 census 不减少 `1,250 + 250 + 56 + 17` 个 RQ2 待签项目，也不清除 RQ3 或投稿元数据 blocker

## 2026-07-15

### 1. 已完成：权威远端配置校正与连通性核验

产物：

- `/home/xiaoyuliang/code/vuln-adj/AGENTS.md`
- `/home/xiaoyuliang/code/vuln-adj/docs/plans/project_progress_log.md`
- `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj/AGENTS.md`
- `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj/docs/plans/project_progress_log.md`

验证：

- 已使用 `ssh-vuln-adj` 对应配置连接 `xiaoyuliang@100.101.249.5`。
- 已在 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj` 运行 `hostname`，确认主机名为 `code-defender`。
- 已核查远端项目根目录为 `/home/xiaoyuliang/code/vuln-adj`。
- 已确认权威远端已包含 canonical RQ2 模板、RQ3 `gold_audit` 模板、guarded evaluators 和 COSE paper package，资产比本地 fallback 完整。

当前效果：

- 后续结果生成与实验运行统一以 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj` 为权威环境。
- 仓库 Markdown 叙事中的旧主机、旧用户目录和旧节点名已机械校正；历史数据与结果文件中的 provenance 字段未改写。
- Codex 可按安全专家流程生成逐条、证据可追溯的 expert-adjudicated gold candidate；由于标注者不是人类，在作者人工复核签收前不得称为 `human-gold`。

未验证：

- 本节只完成环境与叙事校正，尚未填写 RQ2/RQ3 canonical audit rows，也未运行 gold-backed evaluator。
- 远端工作树已有大量未提交改动，本轮没有回滚或覆盖与当前任务无关的文件。

下一步：

- 在权威远端审计 RQ2/RQ3 模板、证据覆盖与 evaluator gate。
- 生成带 annotator provenance 的 expert-adjudicated gold candidate，并运行质量检查与候选标签实验。
- 作者人工复核并签收后，再将相应行升级为 human-gold 并报告 gold-backed 指标。

### 2. 已完成并在权威远端重跑：RQ1 matched-row 字段覆盖分母修复

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq1_discrepancy_distribution/bootstrap_field_coverage.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq1_discrepancy_distribution/bootstrap_field_coverage_summary.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq1_discrepancy_distribution/bootstrap_field_coverage_summary.md`

验证：

- 已在权威远端通过 `py_compile`，并使用现有 `100032` 行对齐数据实际重跑。
- 已新增 matched NVD non-empty 计数与比率，并加入字段分区断言。
- 已将重跑结果同步回本地同名 `results/rq1_discrepancy_distribution/` 目录。

当前效果：

- 对齐总行数 `100032`，NVD-GHSA 匹配行 `8066`，匹配率 `8.0634%`。
- 修复前表格标题写的是 matched rows，但 NVD non-empty rate 使用了全部 `100032` 行作为分母；修复后 NVD、GHSA 与 both rate 均以 `8066` 个 matched rows 为分母。
- 修复后的 matched-row 覆盖率：`severity` 为 NVD `99.5909%`、GHSA `100.0000%`、both `99.5909%`；`references` 为 `99.6405%`、`100.0000%`、`99.6405%`；`affected` 为 `70.5926%`、`99.4793%`、`70.2579%`。

未验证：

- 本次只修复覆盖率统计分母，没有改变对齐结果或字段差异类型 baseline。
- 当前 `8.0634%` 是以 NVD 全集为分母的交集覆盖率，不能直接解释为 GHSA 的整体数据质量或字段正确率。

下一步：

- 在论文表格和正文中统一 matched-row 分母及限定语。
- 继续核对 RQ1 discrepancy 分布与论文 package 中的数字是否引用了修复前的覆盖率。

### 3. 已实现并部分运行：AI 安全专家候选标注与候选指标

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/run_expert_candidate_annotation.py`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/expert_candidate_annotation_prompt.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/expert_candidate_validation/evaluate_expert_candidate_labels.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/raw/`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_metrics.md`

验证：

- 新增脚本已在本地和权威远端通过 `py_compile`。
- 已在权威远端完成 RQ2 与 RQ3 severity 的 smoke test，并对 RQ2 `published` 标签合同、RQ2 source 字段和证据 URL 可追溯性做程序化约束。
- 已在权威远端使用 `--allow-partial` 实际运行候选 evaluator，并将候选行、请求日志和结果同步回本地。
- 所有候选行均记录 `label_is_human=false`、`candidate_status=unreviewed`、模型、时间、prompt 与输入 provenance。

当前效果：

- RQ2 primary 已生成 `47/300` 条，RQ2 same-model review 已生成 `45/60` 条；RQ3 severity 已生成 `46/80` 条；RQ3 affected_versions 为 `0/100`。
- RQ2 primary 部分样本上，deterministic baseline 与候选标签 agreement `0.8936`、macro-F1 `0.8439`；只有 `8` 条 primary/review 重叠，same-model repeatability 为 `0.7500`、kappa `0.6279`。
- RQ3 severity 部分样本中 `13/46` 条标记需要人工复核；候选与 `silver_v2` 的 discrepancy-label agreement `0.8043`，但 adjudicated-source agreement 只有 `0.3261`。
- 在这 `46` 条候选上，`evidence_score_baseline` agreement `0.1957`、macro-F1 `0.1231`；该现象只说明当前候选子集与旧 silver/evidence baseline 的来源裁决不稳定，不能据此宣称最终方法退化或候选标签正确。

未验证：

- 这些产物是 AI security-expert candidate，不是 human-gold；尚未经过作者逐条复核和签收。
- RQ2 review 是同一模型复标，不是独立人工标注者；其 agreement/kappa 不能写成人工标注者一致性。
- 当前覆盖不完整且 RQ3 affected_versions 无候选行，部分指标不能作为最终论文结果。
- 主接口在续跑时返回 HTTP `402` insufficient API quota；fallback 接口反复出现 TLS `UNEXPECTED_EOF_WHILE_READING`，因此没有伪造或补齐剩余标签。
- 远端旧 `.venv` 仍指向失效路径和 Python 3.6；本轮实际使用远端 system Python 3.13，不能写成虚拟环境已修复。

下一步：

- 补充主接口配额或修复 fallback TLS 后，使用 `--resume` 完成 `300/60/80/100` 候选覆盖。
- 优先人工复核 RQ3 severity 中 `needs_human_review=true` 的行和 candidate/silver source 不一致行。
- 作者签收后另行生成 canonical human-gold 文件，再运行 guarded gold evaluator；候选文件本身不得直接改名为 human-gold。

### 4. 已修复解释器选择并重跑：COSE package validator

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/paper_artifacts/validate_cose_package.py`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_package_manifest.json`

验证：

- 首次使用远端 system Python 3.13 运行 validator 时，发现其子生成器硬编码调用失效的 `.venv/bin/python`（实际为 Python 3.6），共触发 `10` 个 `from __future__ import annotations` 语法错误。
- 已将子生成器解释器最小修改为当前 validator 的 `sys.executable`，并通过远端 `py_compile`。
- 已在权威远端重新运行 `validate_cose_package.py --skip-latex-build`，manifest 已重写并同步回本地。

当前效果：

- 解释器语法错误已消除，validator 进入真实的派生产物一致性检查。
- 当前仍为 `status=fail`、`submission_ready=false`。
- 已对原 `6` 组 byte mismatch 做语义 diff：差异主要是旧本地根目录 provenance；`rq3_silver_sensitivity` 另有 Python 版本造成的浮点末位表示差异，统计含义未变。
- 已按当前输入原位重生成相关派生产物并再次运行 validator；byte-identical 失败已全部消除，当前只剩 `cose_latex` 生成器缺少 ImageMagick `convert` 这一项执行失败。
- 独立 submission blockers 仍包括：RQ2 primary/reviewer canonical labels 为空、RQ3 human audit 为 severity `0/80 final` 与 affected_versions `0/100 final`，以及投稿元数据/声明占位符未填写。

未验证：

- 尚未安装 ImageMagick，也未完成 LaTeX 全量重生成。
- validator 修复只解决环境解释器选择，不改变论文方法或实验指标。

下一步：

- 在可控环境补齐 ImageMagick 或为 SVG/PNG 转换提供可复现的替代依赖，然后重跑 validator。
- canonical human-gold 与投稿元数据完成前，保持 `submission_ready=false`。

### 5. 已完成：双 agent 独立审计与 gold evaluator 合同收紧

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/evaluate_rq2_manual_labels.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/evaluate_rq3_human_audit.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/analyze_rq3_human_audit_readiness.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/rq3/gold_audit/README.md`
- `/home/xiaoyuliang/code/vuln-adj/scripts/build_rq3_gold_audit_templates.py`
- `/home/xiaoyuliang/code/vuln-adj/docs/annotation_guidelines/rq2_discrepancy_typing.md`
- `/home/xiaoyuliang/code/vuln-adj/docs/plans/plan_b_cose.md`

验证：

- 已启动两个只读 agent，分别从论文审稿与实验复现角度独立核对远端资产；两者均确认 RQ1 仅达到 descriptive baseline，RQ2/RQ3 尚无 human-gold-backed performance。
- 已核实 RQ2 guideline 允许 `uncertain`，但原 manual evaluator 将其判为非法；现已改为合法完成标签，并从五分类 accuracy/macro-F1 中单独排除和计数。
- 已核实 RQ3 原 evaluator 接受 final 行的 `review_status=not_reviewed` 且无条件写 `gold_label_is_human=true`；现已要求 `review_status=reviewed`、非空 `reviewer_id`，且 reviewer 必须与 annotator 不同。
- 修改后的四个 Python 文件已在权威远端通过 `py_compile`。
- RQ2 合同测试使用 `1` 个 determinate + `1` 个 uncertain 行，结果为 input `2`、evaluated `1`、excluded uncertain `1`。
- RQ3 合同测试已确认 `not_reviewed`、缺失 reviewer 和 annotator/reviewer 相同三种情况均被拒绝；当前 canonical severity `80` 行全为 draft，guarded evaluator 以退出码 `2` 拒绝且不写 metrics。

当前效果：

- 两个 agent 都确认 AI candidate 不能代表总体：RQ2 当前 `47` 条 primary 全来自 severity，RQ3 当前是顺序前 `46` 条 severity 样本。
- Plan B 已将 RQ3 计划从错误的 `150 = 80 + 70` 校正为现有模板对应的 `180 = 80 + 100`，并补回 RQ1 表中 severity `33 incomplete` 与 cwe_ids `23 representation_discrepancy`。
- RQ3 readiness 已在远端重跑；severity 仍为 `0/80 final`，affected_versions 仍为 `0/100 final`。

未验证：

- 独立 agent 审计是代码和产物复核，不是人类标注，也不增加 human-gold 行数。
- evaluator 只能验证记录的 provenance 字段与 review 状态，不能从机器层面证明填写者的现实身份；论文仍需如实披露标注流程。
- 当前 RQ2/RQ3 canonical 文件尚未填写，不存在可报告的 gold-backed accuracy、macro-F1、source decision 或人工一致性结果。

下一步：

- 先按新合同完成人工 primary/reviewer 标注与签收，再运行 guarded evaluator。
- RQ2 指标必须按五字段报告，不能外推当前仅 severity 的 `47` 条 candidate。
- RQ3 应优先复核 candidate/silver source 不一致行，随后再决定是否调整 evidence baseline。

### 6. 已实现并在权威远端运行：均衡候选调度、人工复核包与优先级诊断

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/run_expert_candidate_annotation.py`
- `/home/xiaoyuliang/code/vuln-adj/scripts/build_expert_candidate_review_packets.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/expert_candidate_validation/validate_human_review_packets.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/expert_candidate_validation/analyze_candidate_coverage_and_priority.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/review_packets/`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/human_review_packet_readiness.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_coverage_diagnostics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_review_priority.jsonl`

验证：

- 新增与修改脚本已在本地和权威远端通过 `py_compile`。
- RQ2 默认调度改为五字段 round-robin；`--plan-only --max-new-rows 5` 已验证下一批正好覆盖 severity、published、references、affected_versions、cwe_ids 各 `1` 条。
- `--resume` 仍按 sample ID 排除已完成行；当前 primary pending 为 `253`，不会覆盖既有 `47` 条。
- 已生成 `138` 条隔离复核包：RQ2 primary `47`、RQ2 review `45`、RQ3 severity `46`；RQ3 affected_versions 因 candidate 文件不存在而明确列为 missing。
- review readiness 普通模式通过且无结构错误；`--require-signed` 以退出码 `2` 拒绝当前包，确认未签收行不能被视为 human-gold。
- 已用 `/tmp` 副本构造 `1` 条完整双人签收记录；修复自定义 `--input-dir` 路径解析后，`--require-signed` 正向测试以 `signed_human_rows=1`、退出码 `0` 通过。真实复核包未被修改。
- 已验证请求日志会记录 `request` 与 `response_error` 事件；最新主接口 402 已写入 error event。

当前效果：

- 复核包共 `138` 条，`signed_human_rows=0`、`pending_rows=138`、`validation_error_count=0`。
- 覆盖诊断确认 RQ2 primary 为输入前缀 `47/300`，severity 覆盖 `47/60`，其他四字段均为 `0/60`；RQ3 severity 为输入前缀 `46/80`。
- RQ2 review 覆盖 `45/60`：severity、published、references 各 `12/12`，affected_versions `9/12`，cwe_ids `0/12`。
- 风险 worklist 共 `138` 条，其中 `60` 条 priority score 大于 0；RQ3 severity 中 candidate/silver label 分歧 `9/46`，source 分歧 `31/46`，candidate 主动要求人工复核 `13/46`。

未验证：

- 复核包只是人工工作入口，尚无现实人类填写 annotator、独立 reviewer、author sign-off 与时间字段，因此 human-gold 仍为 `0`。
- API 复查未恢复可用性：主 Responses 路由返回 HTTP `402 insufficient API quota`，主 Chat 路由超时，fallback 仍为 TLS `UNEXPECTED_EOF_WHILE_READING`。
- round-robin 只消除后续 partial run 的字段顺序偏差，不能反向使已有 47 条 primary 成为五字段代表性样本。

下一步：

- 先人工处理 priority worklist 中 `60` 条高风险行，尤其是 RQ3 source disagreement 行。
- 接口恢复后使用 `--resume` 与 round-robin 调度优先补齐 RQ2 五字段覆盖，再补 RQ3 affected_versions。
- 至少一条真实双人签收通过 `--require-signed` 前，不生成或报告 human-gold 指标。

### 7. 已实现并在权威远端重跑：affected_versions package/range selective baseline（初版，已被第 8 节纠正）

状态说明：本节记录初次运行。初版把字符串立即后继边界当作区间等价，因
`<=12.3` 与 `<12.4` 之间仍可能存在 `12.3.1`，该假设不足以支持 `both`。第 8 节
已收紧规则并重跑；本节的 `0.33` 结果不得继续作为当前结果引用。

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/affected_versions_semantic_baseline.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/test_affected_versions_semantic_baseline.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/evaluate_affected_versions_silver_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/evaluate_rq3_human_audit.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_silver_v2_eval_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_artifact_tables.json`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_artifact_tables.md`

验证：

- 新增 package canonical/leaf 对齐、保守版本解析、规范化区间等价和 immediate-successor inclusive/exclusive 边界等价规则；point-in-range 仅作诊断，不能单独输出 `both`。
- 本地与权威远端均通过 `py_compile` 和 focused unit test；测试覆盖包名不匹配拒答、leaf 对齐、边界等价覆盖单边 token、point-in-range 不升级和不可解析版本。
- 已在权威远端对 `100` 条 affected_versions silver-v2 样本重跑 `6` 个 baseline，共生成 `600` 条预测。
- package profile 为 exact/canonical overlap `23`、leaf-only overlap `22`、no overlap `55`；range relation 为 not proven `81`、unparseable `14`、successor-boundary equivalent `4`、NVD points within GHSA ranges `1`。
- 已将两个新方法接入未来的 human-audit evaluator 和 COSE 表格；当前 `100/100` 条 human audit 仍为 draft，guarded evaluator 以退出码 `2` 拒绝且未生成 gold metrics。
- 已重跑 threshold sensitivity、evidence-source reliability 和 COSE table builder。`validate_cose_package.py --skip-latex-build` 未出现新的派生产物不一致，只保留既有 ImageMagick `convert` 缺失失败。
- 上述结果及派生表格已同步回本地同名目录。

当前效果：

- `version_token_support_baseline`：silver agreement `0.57`、macro-F1 `0.2838`、coverage `0.97`、selective agreement `0.5876`。
- `package_gated_token_baseline`：silver agreement `0.32`、macro-F1 `0.2056`、coverage `0.45`、selective agreement `0.6222`。
- `package_range_evidence_baseline`：silver agreement `0.33`、macro-F1 `0.2126`、coverage `0.45`、selective agreement `0.6444`。
- range 规则相对 package-gated token 在相同覆盖率下多判对 `1` 条，但 package gating 相对 token baseline 大幅降低覆盖率和总体一致率；当前只能解释为 selective risk-coverage trade-off，不能写成整体性能提升。

未验证：

- 所有指标仍以 evidence-aware LLM silver 为参照，不是 human-gold performance。
- 当前版本解析主要采用 PEP 440 兼容表示；尚未覆盖不同生态的全部版本语义、Git revision、发行版 backport 和复杂 union range。
- 当前只有 `4` 条 immediate-successor 边界等价样本，且没有人工签收，不能据此证明规则泛化有效。

下一步：

- 在 `100` 条 affected_versions human audit 中优先复核 package identity 不可比、range relation 可解析和语义规则改变 token 决策的样本。
- human-gold 可用后，同时报告 coverage、selective agreement、risk-coverage 曲线和按 package/range 类型分层结果，再决定是否保留 package gating。
- 不再把 token 文本命中或当前银标一致率表述为已完成的语义版本范围裁决。

### 8. 已实现并在权威远端重跑：边界规则纠正、canonical token 消融与 affected_versions 候选扩展

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/affected_versions_semantic_baseline.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/analyze_canonical_version_token_effect.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/build_canonical_disagreement_review.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/raw/rq3_affected_versions.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/review_packets/rq3_affected_versions.review.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/canonical_version_token_effect.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/canonical_version_token_disagreement_review.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/human_review_packet_readiness.json`

验证：

- 将 immediate-successor 关系改为 `successor_boundary_candidate` 诊断；只有规范化后完全相同的区间，或两侧均有独立 token 证据时，才允许输出 `both`。
- canonical matcher 只接受 release component 数量一致的别名；focused test 已验证 `3.0.0.Final` 可匹配 `3.0.0`，而 `CVSS v4.0` 不会误匹配 `4.0.0`。
- 本地与权威远端 focused tests、`py_compile` 和 AI candidate 合同校验均通过。
- 已在权威远端对 `100` 条 affected_versions silver-v2 样本重跑 `8` 个 baseline，共生成 `800` 条预测。
- canonical effect 分析确认 raw/canonical token 在 `10/100` 条样本上改变决策：raw-only 正确 `4` 条、canonical-only 正确 `4` 条，总体正确数均为 `57`。
- 已逐条基于已抓取证据生成 `14/100` 条定向 AI security-expert candidate；全部设置 `label_is_human=false`、`candidate_status=unreviewed`，合同校验通过。
- 已重建复核包并验证：总计 `152` 条，signed human rows `0`、pending `152`、结构错误 `0`；affected_versions 包含 `14` 条，其中 `8` 条主动要求人工复核。
- `validate_human_review_packets.py --require-signed` 以退出码 `2` 拒绝当前复核包；severity 与 affected_versions guarded human-audit evaluator 也分别以退出码 `2` 拒绝 `0` 条 final row。
- 已重跑 COSE table builder 和 `validate_cose_package.py --skip-latex-build`；派生产物检查没有新增不一致，唯一执行失败仍是缺少 ImageMagick `convert`，并继续列出 RQ2 空标签、RQ3 `0/180 final` 和投稿元数据占位符三类 submission blockers。

当前效果：

- silver 上 raw token：agreement `0.57`、macro-F1 `0.2838`、coverage `0.97`、selective agreement `0.5876`。
- silver 上 canonical token：agreement `0.57`、macro-F1 `0.2843`、coverage `0.98`、selective agreement `0.5816`；未形成总体提升。
- silver 上 package raw/range 均为 agreement `0.32`、macro-F1 `0.2056`、coverage `0.45`、selective agreement `0.6222`；纠正后的 range 规则没有额外收益。
- silver 上 package canonical 为 agreement `0.30`、macro-F1 `0.1936`、coverage `0.45`、selective agreement `0.5778`，低于 package raw。
- `14` 条定向 candidate 中，raw token 一致 `7/14`，canonical token 一致 `10/14`；package raw/range 一致 `6/14`，package canonical 一致 `7/14`。该样本按高信息分歧点选择，不代表总体分布。
- affected_versions candidate 分布为 `7 factual_conflict`、`4 representation_discrepancy`、`1 incomplete`、`2 uncertain`；来源裁决为 `8 both`、`5 nvd`、`1 ghsa`。

未验证：

- 所有 `14` 条均为 Codex 证据裁决候选，不是现实人类标注，也未经过独立 reviewer 和 author sign-off。
- canonical token 仍会受到过时 change-history 版本、无关历史发布页、prerelease qualifier 丢失和多版本体系歧义影响；不能把更宽松的 token 命中当作来源可靠性。
- silver 与 AI candidate 都不等价于 human-gold；当前 RQ3 human final 仍为 severity `0/80`、affected_versions `0/100`。

下一步：

- 优先人工复核 affected_versions 中 `8` 条 `needs_human_review=true` 记录，以及 canonical/raw 决策变化的 `10` 条样本。
- 下一版方法应显式建模证据页面角色与版本上下文，过滤 superseded change history 和无关 release token；实现前先用复核结果固化错误类型。
- 完成真实双人签收后，才运行 guarded gold evaluator 并决定是否保留 canonical token、package gate 与 range 规则。

### 9. 已实现并在权威远端运行：双 agent affected_versions 批次裁决与候选扩展

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/import_expert_candidate_batch.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq3_affected_dual_agent_001_021.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/raw/rq3_affected_versions.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/review_packets/rq3_affected_versions.review.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_coverage_diagnostics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/canonical_version_token_effect.json`

验证：

- 两个 Codex agent 分别只读审查 `001-010` 与 `012-021`，样本不重叠；均按已抓取正文、包身份和版本分支判断，证据不足时保留 `uncertain`。
- 新增批次导入器统一补充 `label_is_human=false`、annotator/pass provenance，并在写入前拒绝重复 sample ID、CVE/field 不匹配和不可追溯 evidence URL。
- 导入器已在权威远端通过 `py_compile`；dry-run 报告 existing `14`、new `20`、result `34`，实际导入后同样为 `34`。
- `evaluate_expert_candidate_labels.py --allow-partial` 已在权威远端通过，affected_versions `candidate_contract_validated=true`。
- 重建复核包前先确认旧包 signed human rows 为 `0`；重建后总计 `172` 条、pending `172`、结构错误 `0`。
- 已重跑 coverage/priority、canonical effect 和 COSE table builder，并将结果同步回本地。
- 重复执行同一批次 dry-run 时，导入器以退出码 `1` 拒绝已存在的 `001`；`validate_human_review_packets.py --require-signed` 以退出码 `2` 拒绝当前 `0/172` 签署状态。
- 权威远端 `git diff --check` 通过，旧主机/旧目录 Markdown 扫描为零命中；COSE validator 仍仅因缺少 ImageMagick `convert` 执行依赖而失败，并保持 `submission_ready=false`。

当前效果：

- affected_versions candidate 覆盖为 `34/100`；标签分布为 `10 factual_conflict`、`7 representation_discrepancy`、`2 incomplete`、`15 uncertain`。
- 来源裁决为 `16 nvd`、`13 both`、`2 ghsa`、`3 abstain`；`23/34` 主动要求人工复核。
- candidate 与 silver 的 label agreement 为 `0.4118`、source agreement 为 `0.6765`，说明 silver 与证据裁决在差异类型上仍不稳定。
- 34 条 candidate 上 raw token 一致 `20/34`，canonical token 一致 `23/34`；package raw 为 `15/34`，package canonical 为 `16/34`。
- 复核 worklist 共 `172` 条，其中 `91` 条 priority score 大于 `0`。

未验证：

- 两个 agent 均属于 Codex/同一模型家族，不能视为独立人类 annotator 或 reviewer；新增行仍是 AI expert candidate。
- 34 条由连续前缀 `21` 条与此前高信息样本组成，不是总体代表性抽样，候选一致率不能写成最终性能。
- 新批次中 `15/20` 条因包映射、发布分支或正文缺失被标为 uncertain/待复核；扩大字符串规范化不能消除这些证据缺口。

下一步：

- 继续按不重叠批次审查 `022-100`，优先使用厂商公告、修复提交和明确版本映射；无充分证据时保留 abstain/uncertain。
- 优先补抓 Adobe、Microsoft、GitHub commit/release 等当前超时或空正文证据，再复核 package-identity 条目。
- 将 `23` 条 affected_versions 高风险候选加入真实 reviewer/author sign-off 流程；签收前不生成 human-gold 指标。

### 10. 已实现并在权威远端运行：affected_versions 双 agent 第二批裁决与 54 条候选诊断

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq3_affected_dual_agent_022_043.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/scripts/import_expert_candidate_batch.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/raw/rq3_affected_versions.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/review_packets/rq3_affected_versions.review.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_coverage_diagnostics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_review_priority.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/canonical_version_token_effect.json`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_package_manifest.json`

验证：

- 两个 Codex agent 分别只读裁决 `022-032`（排除既有 `029`）和 `033-043`（排除既有 `038`），各 `10` 条且样本不重叠；主 agent 按证据合同复核并固化批次。
- 导入器新增 label/source/version-reasoning/confidence 枚举校验，并强制 `uncertain` 或 low-confidence 行进入人工复核；本地和权威远端 `py_compile` 均通过。
- 本地合同校验在导入前检出了固化过程中的不可追溯 URL，并按证据清单中的精确 URL 修正；最终 `20` 条全部通过 CVE/field、URL、枚举和唯一性检查。
- 权威远端 dry-run 报告 existing `34`、new `20`、result `54`；实际导入后为 `54`，且 `evaluate_expert_candidate_labels.py --allow-partial` 报告 `candidate_contract_validated=true`。
- 重建复核包前确认旧包 `172` 条中 signed human rows 为 `0`；重建后共 `192` 条、pending `192`、结构错误 `0`，其中 affected_versions 为 `54` 条。
- 已在权威远端重跑 candidate evaluator、coverage/priority、canonical effect、COSE table builder 和 package validator，并将生成结果同步回本地。
- `validate_human_review_packets.py --require-signed`、severity guarded evaluator 和 affected_versions guarded evaluator 均以退出码 `2` 拒绝；两类 RQ3 audit 仍分别为 `0/80 final` 和 `0/100 final`。
- COSE validator 保持 `submission_ready=false`；派生产物未出现新的不一致，唯一执行失败仍为缺少 ImageMagick `convert`。

当前效果：

- 第二批 `20` 条标签分布为 `5 factual_conflict`、`1 incomplete`、`1 representation_discrepancy`、`13 uncertain`；来源为 `11 nvd`、`3 ghsa`、`2 both`、`1 neither`、`3 abstain`，其中 `18/20` 要求人工复核。
- affected_versions candidate 累计覆盖 `54/100`；标签分布为 `15 factual_conflict`、`3 incomplete`、`8 representation_discrepancy`、`28 uncertain`；来源为 `27 nvd`、`15 both`、`5 ghsa`、`1 neither`、`6 abstain`，`41/54` 要求人工复核。
- candidate 与 silver 的 label agreement 为 `0.3704`，source agreement 为 `0.5926`；该下降发生在定向扩展样本上，不能解释为总体性能变化。
- `54` 条 candidate 上 raw token 一致 `27/54`，canonical token 一致 `30/54`；canonical 改变 `10` 条决策，其中 raw-only 正确 `3` 条、canonical-only 正确 `6` 条。
- package raw/range 一致 `20/54`、coverage `0.4630`、selective agreement `0.6000`；package canonical 一致 `21/54`、coverage `0.4630`、selective agreement `0.6400`。这些是非代表性 AI candidate 诊断，不是 human-gold performance。
- 复核 worklist 共 `192` 条，其中 `110` 条 priority score 大于 `0`；真实 signed human rows 仍为 `0`。

未验证：

- 两个 agent 和主 agent 都属于 Codex 流程，不是现实人类 annotator、独立 reviewer 或 author；所有新增行仍为 `label_is_human=false` 的 unreviewed candidate。
- `54` 条由连续前缀 `43` 条和此前高信息样本组成，且第二批大量样本因 package identity、分支映射或正文缺失被选为 `uncertain`，不代表 `100` 条模板总体分布。
- candidate 上 canonical token 的一致数高于 raw token，但 silver 全体 `100` 条上两者仍同为 `57` 条正确；尚无证据支持将 canonical token 定为最终方法。
- COSE submission blockers 仍包括 RQ2 canonical 标签为空、RQ3 human final 为 `0/180`，以及投稿元数据/声明占位符未填写。

下一步：

- 先对 affected_versions 的 `41` 条 `needs_human_review=true` 候选进行现实人类复核，优先处理 priority `15` 的 `17` 条和 package-identity/abstain 项。
- 继续以不重叠批次审查 `044-100` 的未覆盖样本；补抓直接厂商公告和 release/commit 映射，证据不足时继续保留 uncertain/abstain。
- 只有独立 reviewer、author sign-off 与 `--require-signed` 门禁通过后，才将相应行提升为 canonical human-gold 并运行最终 evaluator。

### 11. 已实现并在权威远端运行：affected_versions 第三批双 agent 裁决与 74 条候选诊断

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq3_affected_dual_agent_044_069.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/scripts/import_expert_candidate_batch.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/raw/rq3_affected_versions.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/review_packets/rq3_affected_versions.review.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_coverage_diagnostics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_review_priority.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/canonical_version_token_effect.json`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_package_manifest.json`

验证：

- 两个 Codex agent 分别只读裁决 `044,045,046,047,049,051,052,054,055,057` 与 `059,060,061,062,064,065,066,067,068,069`，各 `10` 条且样本不重叠；主 agent 逐条核对结构化范围与已抓取正文。
- 主复核纠正了 Magick.NET 与原生 ImageMagick 的包映射表述，并将 TensorFlow 的裁决值收紧为已被正文支持的 `<2.11.1` affected、`2.11.1/2.12.0` fixed，避免把已修复版本留在 affected 区间。
- 导入器进一步要求 adjudicated source/value 一致、`uncertainty_notes` 为字符串、evidence URL 唯一且非空，并拒绝 `fetch_status != ok` 的链接作为证据。
- 既有 `40` 条批次均通过加固后的回归合同；专门构造的抓取失败 URL 和 `abstain` 非空裁决值均以退出码 `1` 被拒绝。
- 权威远端 dry-run 报告 existing `54`、new `20`、result `74`；实际导入后为 `74`，candidate evaluator 报告 `candidate_contract_validated=true`。
- 重建复核包前确认旧包 `192` 条中 signed human rows 为 `0`；重建后共 `212` 条、pending `212`、结构错误 `0`，其中 affected_versions 为 `74` 条。
- 已在权威远端重跑 candidate evaluator、coverage/priority、canonical effect、COSE table builder 和 package validator，并将结果同步回本地。
- `validate_human_review_packets.py --require-signed`、severity guarded evaluator 和 affected_versions guarded evaluator 均以退出码 `2` 拒绝；RQ3 human final 仍为 severity `0/80`、affected_versions `0/100`。
- COSE validator 保持 `submission_ready=false`；唯一执行失败仍为缺少 ImageMagick `convert`，三类 submission blockers 未变化。

当前效果：

- 第三批 `20` 条标签分布为 `1 equivalent`、`6 factual_conflict`、`1 temporal_discrepancy`、`12 uncertain`；来源为 `8 nvd`、`3 ghsa`、`2 both`、`1 neither`、`6 abstain`，其中 `16/20` 要求人工复核。
- affected_versions candidate 累计覆盖 `74/100`；标签分布为 `1 equivalent`、`21 factual_conflict`、`3 incomplete`、`8 representation_discrepancy`、`1 temporal_discrepancy`、`40 uncertain`；来源为 `35 nvd`、`17 both`、`8 ghsa`、`2 neither`、`12 abstain`，`57/74` 要求人工复核。
- candidate 与 silver 的 label agreement 为 `0.3378`，source agreement 为 `0.5541`；扩展后分歧继续增大，说明 silver 对复杂版本和包身份样本不稳定。
- `74` 条 candidate 上 raw token 一致 `31/74`，canonical token 一致 `34/74`；canonical 改变 `10` 条决策，其中 raw-only 正确 `3` 条、canonical-only 正确 `6` 条。
- package raw/range 一致 `25/74`、coverage `0.4189`、selective agreement `0.4839`；package canonical 一致 `26/74`、coverage `0.4189`、selective agreement `0.5161`。这些仍是非代表性 AI candidate 诊断。
- 复核 worklist 共 `212` 条，其中 `130` 条 priority score 大于 `0`；affected_versions 中 priority `15` 为 `24` 条，真实 signed human rows 仍为 `0`。

未验证：

- 两个 agent 和主 agent 都属于 Codex 流程，不是现实人类 annotator、独立 reviewer 或 author；新增行仍为 `label_is_human=false` 的 unreviewed candidate。
- 当前候选虽已覆盖 `74%`，但 `40/74` 为 uncertain，且连续输入前缀为 `70` 条；该分布不能外推到全部 NVD-GHSA affected_versions 差异。
- candidate 上 canonical token 多一致 `3` 条，但 silver 全体 `100` 条上 raw/canonical 仍同为 `57` 条正确；package canonical 在 silver 上还低于 package raw，不能选为最终方法。
- COSE submission blockers 仍包括 RQ2 canonical 标签为空、RQ3 human final 为 `0/180`，以及投稿元数据/声明占位符未填写。

下一步：

- 继续完成剩余 `26` 条 affected_versions 候选，优先处理有直接厂商正文、release 和修复提交的记录；抓取不足时保留 uncertain/abstain。
- 现实人类复核优先处理 affected_versions 的 `57` 条 `needs_human_review=true`，尤其是 priority `15` 的 `24` 条、source=abstain/neither 和 package-identity 项。
- 完成独立 reviewer、author sign-off 与 `--require-signed` 后，才能将相应行提升为 canonical human-gold 并运行最终 evaluator。

### 12. 已实现并在权威远端运行：affected_versions 双 agent 对比收口与 100 条候选诊断

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq3_affected_dual_agent_071_100.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/scripts/import_expert_candidate_batch.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/raw/rq3_affected_versions.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/review_packets/rq3_affected_versions.review.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_coverage_diagnostics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_review_priority.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/canonical_version_token_effect.json`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_artifact_tables.json`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_package_manifest.json`

验证：

- 两个 Codex agent 分别只读裁决 `071,072,073,074,076,077,078,079,080,081,083,084,085` 与 `086,087,088,089,090,093,094,095,096,097,098,099,100`，各 `13` 条且样本不重叠；主 agent 逐条复核其结构化范围、包身份和已抓取正文。
- 主复核将样本 `073` 从 representation discrepancy 调整为 `uncertain/both`：.NET/Visual Studio 产品版本与 System.Text.Json NuGet 版本属于不同版本空间，现有证据不足以证明只是表示差异。
- 最终批次合同校验通过，共 `26` 条且 sample_id 唯一；导入器进一步拒绝证据正文为空的 URL。既有 `60` 条批次通过回归合同，专门构造的空正文证据以退出码 `1` 被拒绝。
- 权威远端 `py_compile` 通过；dry-run 报告 existing `74`、new `26`、result `100`，实际导入后 affected_versions candidate 为 `100` 条，且 evaluator 报告 `candidate_contract_validated=true`。
- 重建复核包前确认旧包 `212` 条中 signed human rows 为 `0`；重建后共 `238` 条、pending `238`、结构错误 `0`，其中 affected_versions 为 `100` 条。
- 已在权威远端重跑 candidate evaluator、coverage/priority、canonical effect、COSE table builder 和 package validator，并将候选、复核包和结果同步回本地。
- `validate_human_review_packets.py --require-signed`、severity guarded evaluator 和 affected_versions guarded evaluator 均以退出码 `2` 拒绝；RQ3 human final 仍为 severity `0/80`、affected_versions `0/100`。
- COSE validator 以退出码 `1` 保持 `submission_ready=false`；唯一执行失败仍为缺少 ImageMagick `convert`，submission blockers 仍是 RQ2 空标签、RQ3 `0/180 final` 和投稿元数据/声明占位符。

当前效果：

- 最终批次 `26` 条标签分布为 `1 equivalent`、`4 factual_conflict`、`1 incomplete`、`2 representation_discrepancy`、`18 uncertain`；来源为 `16 nvd`、`5 both`、`2 ghsa`、`1 neither`、`2 abstain`，其中 `22/26` 要求人工复核。
- affected_versions candidate 已覆盖 `100/100`；标签分布为 `2 equivalent`、`25 factual_conflict`、`4 incomplete`、`10 representation_discrepancy`、`1 temporal_discrepancy`、`58 uncertain`；来源为 `51 nvd`、`22 both`、`10 ghsa`、`3 neither`、`14 abstain`，`79/100` 要求人工复核。
- candidate 与 silver 的 label agreement 为 `0.3300`，source agreement 为 `0.5800`。两者属于同模型家族的非独立诊断，不能作为人工一致性或 gold-backed 性能。
- `100` 条 candidate 上 raw token 一致 `46/100`、coverage `0.97`、selective agreement `0.4742`；canonical token 一致 `49/100`、coverage `0.98`、selective agreement `0.5000`。canonical 改变 `10` 条决策，其中 canonical-only 正确 `6` 条、raw-only 正确 `3` 条。
- package raw/range 一致 `33/100`、coverage `0.45`、selective agreement `0.4889`；package canonical 一致 `34/100`、coverage `0.45`、selective agreement `0.5111`。这些仍是 AI candidate 上的诊断结果，不是 human-gold performance。
- 复核 worklist 共 `238` 条，其中 `154` 条 priority score 大于 `0`；affected_versions 中 priority `15` 为 `32` 条，真实 signed human rows 仍为 `0`。

未验证：

- 两个 agent 和主 agent 都属于 Codex 流程，不是现实人类 annotator、独立 reviewer 或 author；全部 `100` 条 affected_versions 仍是 `label_is_human=false` 的 unreviewed expert candidate。
- affected_versions candidate 已覆盖模板，但其中 `58/100` 为 uncertain，且样本本身来自 factual-conflict 定向抽样；不能把该分布外推到全部 NVD-GHSA 对齐记录。
- candidate 上 canonical token 比 raw token 多一致 `3` 条，但 silver 全体 `100` 条上二者仍同为 `57` 条正确，package canonical 在 silver 上还从 `32` 条降为 `30` 条；不能据此选定最终方法。
- COSE submission blockers 未解除：RQ2 canonical 标签为空、RQ3 human final 为 `0/180`、投稿元数据/声明占位符未填写；远端仍缺 ImageMagick `convert`。

下一步：

- 现实人类复核优先处理 affected_versions 的 `79` 条 `needs_human_review=true`，尤其是 priority `15` 的 `32` 条、source=abstain/neither 和 package-identity 项。
- 补齐 RQ2 primary/reviewer 全字段候选和 RQ3 severity 剩余候选；保持 partial candidate 的字段覆盖与样本偏差说明。
- 完成独立 reviewer、author sign-off 与 `--require-signed` 后，才能将相应行提升为 canonical human-gold，并运行 RQ2/RQ3 guarded evaluators。

### 13. 已实现并在权威远端运行：severity 双 agent 裁决收口与 80 条候选诊断

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq3_severity_dual_agent_047_080.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/raw/rq3_severity.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence_manifest.json`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/review_packets/rq3_severity.review.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_coverage_diagnostics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/rq3_silver_baseline_sensitivity.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/evidence_source_reliability.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/rq3_human_audit_readiness.json`
- `/home/xiaoyuliang/code/vuln-adj/experiments/paper_artifacts/validate_cose_package.py`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_package_manifest.json`

验证：

- 两个 Codex agent 分别独立裁决 severity `047-063` 与 `064-080`，各 `17` 条且不重叠；两份原始 agent 输出均单独通过权威远端导入合同。
- 主 agent 按既有同向量/不同标签规则复核，将 `067`、`068`、`075`、`078` 从 factual conflict 调整为 representation discrepancy；这些记录的 GHSA 显示标签与其 CVSS 向量计算等级不一致，来源支持标签保持不变。
- 证据检查发现 `067` 的旧缓存为 `0/9` URL 成功；在权威远端只重抓该样本后变为 `9/9`，再由缓存重建完整 severity 证据视图。当前 severity `80/80` 样本至少有一条可用证据，证据记录状态为 `415 ok`、`4 http_403`、`3 http_404`、`2 timeout`、`46 url_error`。
- 最终 `34` 条批次 sample_id 为连续 `047-080`、无重复，远端 dry-run 报告 existing `46`、new `34`、result `80`；实际导入后 evaluator 报告 `candidate_contract_validated=true`。
- 重建复核包前确认旧包 `238` 条中 signed human rows 为 `0`；重建后共 `272` 条、pending `272`、结构错误 `0`，其中 severity `80` 条、affected_versions `100` 条。
- 重抓证据后，COSE validator 首次检出 sensitivity、evidence-source reliability 和 human-audit readiness 三组旧派生产物；按各自生成器重跑后恢复 byte-identical。
- readiness validator 原先硬编码 severity `samples_with_ok_evidence=79`；实际提升为 `80` 后会误报失败，已将断言同步更新为 `80`，本地与权威远端 `py_compile` 均通过。
- `validate_human_review_packets.py --require-signed`、severity guarded evaluator 和 affected_versions guarded evaluator 均以退出码 `2` 拒绝未签署或 draft 数据；COSE validator 最终只剩缺少 ImageMagick `convert` 的执行失败。

当前效果：

- 新批次 `34` 条标签分布为 `28 factual_conflict`、`6 representation_discrepancy`；来源为 `19 both`、`12 nvd`、`3 ghsa`，其中 `8/34` 要求人工复核，置信度为 `25 high`、`9 medium`。
- severity candidate 已覆盖 `80/80`；标签分布为 `67 factual_conflict`、`12 representation_discrepancy`、`1 uncertain`；来源为 `29 both`、`27 ghsa`、`23 nvd`、`1 abstain`，`21/80` 要求人工复核。
- severity candidate 与 silver 的 label agreement 为 `0.8000`，source agreement 为 `0.5750`；它们属于同模型家族的非独立诊断，不是人工一致性。
- severity 的四个来源 baseline 中，evidence-score baseline 在 candidate 上最高：agreement `0.4125`、macro-F1 `0.2583`、coverage `1.0`；prefer-GHSA 为 `0.3375`，prefer-NVD 为 `0.2875`，latest-published 为 `0.2750`。该差距只说明固定选边和发布时间规则不足，不能写成 gold-backed 方法性能。
- RQ3 两个主字段 candidate 现均覆盖模板：severity `80/80`、affected_versions `100/100`。复核 worklist 共 `272` 条，其中 `167` 条 priority score 大于 `0`，真实 signed human rows 仍为 `0`。

未验证：

- 两个 agent 和主 agent 都属于 Codex 流程；severity 与 affected_versions 虽已形成完整 expert-adjudicated candidate，但仍全部为 `label_is_human=false`，不是现实人类签署的 human-gold。
- severity 样本来自 factual-conflict 定向抽样，且 `21/80` 仍要求复核；当前来源分布和 baseline agreement 不能外推到全部 NVD-GHSA 对齐记录。
- evidence-score baseline 只达到 `0.4125` agreement，尤其大量预测为 `both` 且难以识别 `ghsa`；尚不支持将现有证据计分规则定为最终裁决方法。
- submission blockers 未解除：RQ2 canonical 标签为空、RQ3 human final 为 `0/180`、投稿元数据/声明占位符未填写；远端仍缺 ImageMagick `convert`。

下一步：

- 先补齐 RQ2 primary 的 affected_versions、published、references、cwe_ids 四个字段候选，修复当前 severity 前缀偏差；same-model review 也需补齐剩余 `15/60`。
- 现实人类签收优先处理 RQ3 中 `100` 条 needs_human_review 候选（severity `21`、affected_versions `79`）以及全局 `167` 条正优先级记录。
- 在独立 reviewer、author sign-off 与 `--require-signed` 通过前，仅报告 candidate/silver diagnostics，不生成 human-gold 性能结论。

### 14. 已实现并在权威远端运行：RQ2 五字段候选与同模型复标候选完整覆盖

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/import_rq2_expert_candidate_batch.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_primary_multi_agent_048_300.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_review_multi_agent_remaining_15.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/raw/rq2_primary.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/raw/rq2_review.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/review_packets/`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_coverage_diagnostics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/expert_candidate_review_priority.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/expert_candidate_validation/human_review_packet_readiness.json`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_package_manifest.json`

验证：

- 多个 Codex agent 分字段生成 RQ2 primary 剩余 `253` 条：severity `13`、published `60`、references `60`、affected_versions `60`、cwe_ids `60`；另一个 agent 独立生成 consistency review 剩余 `15` 条。
- references 的独立复核 agent 检查 `60/60` 条后无改标建议；另一个独立复核 agent 检查 affected_versions `5` 条和 cwe_ids `11` 条歧义候选，均建议保留 `uncertain`。这些复核仍属于 Codex 流程，不是现实人类复核。
- 新导入器严格校验 13 字段 schema、枚举、RQ2 source/value 合同、evidence URL 可追溯性、affected_versions reasoning type 及 uncertain/low review 要求；远端 `py_compile`、已有 `47` 条回归导入和两个负例均通过。
- 最终 primary 批次为连续 ID `048-300`、`253` 行、无缺失或重复；review 批次为 `15` 行、ID 与源模板完全匹配。权威远端 dry-run 分别报告 `47+253=300` 和 `45+15=60`，实际导入后两份 candidate 均无重复，重复导入被退出码 `1` 拒绝。
- 完整模式的 `evaluate_expert_candidate_labels.py` 通过，输出 `candidate_status=unreviewed`、`allow_partial=false`；所有 RQ2 candidate 均为 `label_is_human=false` 和 `candidate_status=unreviewed`。
- 重建复核包前确认旧包 `272` 条中 signed human rows 为 `0`；重建后共 `540` 条、pending `540`、结构错误 `0`。coverage/priority 诊断显示四个 candidate 数据集覆盖率均为 `1.0`，正优先级行 `236` 条。
- 已重跑 canonical-token effect、silver sensitivity、evidence-source reliability、RQ3 human-audit readiness 和 COSE table builder。RQ2 两个人工 evaluator 以退出码 `1` 拒绝空标签；复核签收门禁和两个 RQ3 guarded evaluator 均以退出码 `2` 拒绝未签收/draft 数据。
- COSE package validator 以退出码 `1` 保持 `submission_ready=false`；派生产物未发现新的 byte mismatch，唯一执行失败仍为远端缺少 ImageMagick `convert`。

当前效果：

- RQ2 primary 已覆盖五个字段各 `60` 条，共 `300/300`。标签分布为 equivalent `40`、factual_conflict `32`、incomplete `86`、representation_discrepancy `95`、temporal_discrepancy `30`、uncertain `17`；其中 `20/300` 要求人工复核。
- 剔除 `17` 条 uncertain 后，deterministic baseline 与 candidate 的 agreement 为 `0.8834`、支持类别 macro-F1 为 `0.8934`、determinate coverage 为 `0.9433`。按字段 agreement 为 affected_versions `0.8182`、cwe_ids `0.9184`、published `1.0000`、references `0.7966`、severity `0.8833`。
- same-model review 已覆盖五个字段各 `12` 条，共 `60/60`；标签重复一致 `46/60`，agreement `0.7667`、Cohen's kappa `0.7071`。按字段 agreement 为 affected_versions `0.75`、cwe_ids `0.5833`、published `1.0`、references `0.75`、severity `0.75`。
- RQ2 primary 与 same-model review 合计 `30` 条要求人工复核；全局四个候选数据集共 `540` 条，真实 signed human rows 仍为 `0`。

未验证：

- RQ2 primary 与 review 都由同一模型家族分轮生成；完整覆盖只消除了字段/前缀覆盖缺口，不提供人工金标、独立标注者一致性或外部有效性证据。
- candidate-vs-baseline 指标不是 gold-backed 准确率；published 的 `1.0` agreement 可能反映候选规则与 baseline 定义一致，不能解释为该字段已被人工验证。
- RQ2 canonical primary `300/300` 的 `manual_status` 仍为空，review `60/60` 的 primary/reviewer status 仍为空；RQ3 human final 仍为 `0/180`。
- COSE submission blockers 未解除：缺 RQ2/RQ3 human-gold、投稿元数据/声明仍有占位符，远端仍缺 ImageMagick `convert`。

下一步：

- 先由现实人类处理 `236` 条正优先级 worklist，优先覆盖 RQ2 的 `30` 条 needs_human_review 和 RQ3 的 `100` 条 needs_human_review，再抽检其余低优先级候选。
- 使用独立 annotator/reviewer 身份填写 canonical RQ2 与 RQ3 audit，完成 author sign-off，并要求 `--require-signed` 门禁通过。
- 只有取得 human-gold 后，才运行最终 RQ2/RQ3 evaluator、按字段选择裁决规则并把 gold-backed 指标写入论文。

### 15. 已实现并在权威远端运行：RQ2 references URL normalization 候选引导消融

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_reference_normalization_variants.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/test_reference_normalization_variants.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_variant_diagnostic.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_variant_diagnostic.md`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_changed_cases.review.jsonl`

验证：

- `current_exact` 变体在 primary `60` 条 references、review `12` 条 references 和全量 `8066` 对上均与现有 baseline byte-independent label 结果完全一致，证明实验没有偷换旧方法口径。
- focused tests 覆盖 HTTP/HTTPS、URL 编码行号、Liferay 已知展示参数、GitHub global/repository GHSA URL、Huntr `.com/.dev` bounty ID 和严格子集分类；权威远端 `py_compile` 与测试均通过。
- 探索时发现“删除所有 query”会错误合并依赖 query 标识记录的 VulDB URL，因此最终实现只删除 Liferay CVE 页面已知展示参数；通用 vendor query 保持不变并有 focused test 约束。
- 最佳保守变体依次执行 transport/encoded-line normalization、Liferay known-query normalization 和稳定资源 ID alias；相对现有 baseline 的 primary/review candidate corrections 分别为 `9` 和 `2`，观察到的 regressions 均为 `0`。
- 全量影响为 `56/8066` 条 references 标签变化，全部为 representation_discrepancy→incomplete；触发分布为 transport/line `29`、known query `4`、resource aliases `23`。定向复核包为 `56` 个唯一 CVE，pending `56`、signed `0`、`label_is_human=true` 为 `0`。

当前效果：

- references primary determinate candidate agreement 从 `47/59=0.7966` 提升到 `56/59=0.9492`，macro-F1 从 `0.8108` 到 `0.9634`。
- references same-model review determinate agreement 从 `6/11=0.5455` 提升到 `8/11=0.7273`，macro-F1 从 `0.7059` 到 `0.8421`；两轮一致的 references 子集从 `6/8` 提升到 `8/8`。
- 全 RQ2 primary determinate candidate agreement 从 `250/283=0.8834` 提升到 `259/283=0.9152`，macro-F1 从 `0.8934` 到 `0.9134`。
- 全 RQ2 review determinate candidate agreement 从 `49/55=0.8909` 提升到 `51/55=0.9273`，macro-F1 从 `0.9151` 到 `0.9422`；两轮一致的全字段子集从 `40/43` 提升到 `42/43`。
- 最佳变体只影响全量 references 的 `0.6943%`；该比例表示规则影响面，不是修正准确率。

未验证：

- 所有提升都相对于 AI expert candidate；规则是在检查 candidate 分歧后设计的，primary 数字存在直接选择偏差，review 也只是同模型复标且与 primary 重叠。
- `8/8` 和 `42/43` 仅是小规模两轮一致子集诊断，不是独立 holdout、人工一致性或统计显著性证据。
- `56` 条全量变更尚未由现实人类 annotator、独立 reviewer 或 author 签收；当前没有修改 `scripts/build_field_discrepancies.py` 的生产 baseline，也没有重写 RQ1/RQ2 论文表格。

下一步：

- 独立复核 `56` 条 changed-case worklist，逐条确认 canonical resource identity 和 strict-subset 关系，并填写 annotator/reviewer provenance。
- 只有定向复核和 author sign-off 通过后，才把通过的规则移入生产 normalizer，重跑 `8066` 对字段统计、RQ2 evaluator 和 COSE package。
- references 收口后，再分别对 affected_versions 的边界不稳定项和 cwe_ids taxonomy 关系做保守消融，避免把候选解释直接硬编码为规则。

### 16. 已实现并在权威远端运行：references 双 Agent 候选复核与可选 profile 全量验证

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_reference_normalization_agent_a.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_reference_normalization_agent_b.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_reference_normalization_dual_reviews.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_dual_ai_candidate.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_dual_ai_review.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_dual_ai_review.md`
- `/home/xiaoyuliang/code/vuln-adj/scripts/build_field_discrepancies.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/validate_reference_normalization_profile_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_v2/full_profile/field_discrepancy_stats.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_v2/diagnostics/rq2_typing_diagnostics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_v2/profile_validation.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_v2/profile_validation.md`

验证：

- 两个 Agent 在彼此隔离、不可见候选标签和既有指标、不开启联网检索的条件下，分别审阅同一份 `56` 条 changed-case worklist；两个输入批次均为 `56/56` 完整覆盖，SHA-256 分别为 `3a918b20fde4057fc3e5cd85c69918f04e6a6ed383e43350d55099194634da88` 和 `dc8232ca49b7081c4cab82d2ff848f43e35fdd3dfdfc356eca005d53b87c365a`。
- 两位 Agent 对 `56/56` 条均给出 `approve_incomplete`，标签 exact agreement 为 `1.0`、分歧 `0`；逐字理由相同数为 `0`。由于两边边际分布都只有 `incomplete`，Cohen's kappa 正确记录为 `null`，状态为 `undefined_single_class_marginals`。
- 合并脚本校验行数、ID、触发阶段、decision/status 合同和输入 SHA；缺行、非法 trigger stage、decision/status 不一致三个负例均以退出码 `1` 被拒绝。合并后的 `56` 行全部标记 `label_is_human=false`、`requires_human_signoff=true`、`candidate_status=dual_ai_consensus`。
- `scripts/build_field_discrepancies.py` 新增 `--reference-normalization-profile {current,resource_identity_v1}`；默认值保持 `current`。`current` profile 重跑的字段视图与既有 canonical 文件 byte-identical，双方 SHA-256 均为 `67063d99b5a56c4adde68e811dfa62c04e774313afc869304f505fccd9fb48f1`；统计字段和计数语义一致，只有输入路径 provenance 从旧目录改为权威远端目录。
- 可选 `resource_identity_v1` profile 在权威远端全量 `8066` 对上运行，恰好改变 `56` 条 references 状态、非 references 状态变化 `0`，变化 CVE 集与 worklist 和双 Agent 候选集完全一致。focused tests 和 profile validator 均通过。
- 已重跑 COSE table builder 与 package validator。`submission_ready=false` 保持不变；执行检查只剩远端缺少 ImageMagick `convert`，独立投稿阻塞仍包括 RQ2 canonical 标签为空、RQ3 human final `0/180` 和投稿元数据占位符。

当前效果：

- references 全量分布在可选 profile 下由 representation_discrepancy `300`、incomplete `7763`、factual_conflict `3` 变为 representation_discrepancy `244`、incomplete `7819`、factual_conflict `3`；变化全部为 `56` 条 representation_discrepancy→incomplete。
- 全五字段合计分布相应由 incomplete `12001`、representation_discrepancy `13601` 变为 incomplete `12057`、representation_discrepancy `13545`，其他类别不变。
- 在 AI candidate 诊断口径下，references primary agreement 为 `56/59=0.9492`、macro-F1 `0.9634`；全 RQ2 primary agreement 为 `259/283=0.9152`、macro-F1 `0.9134`。这些数值与消融阶段一致，不是 human-gold 性能。
- profile validator 明确记录 `candidate_backed_profile_validated=true`、`eligible_for_provisional_candidate_analysis=true`、`eligible_for_final_paper_claim=false`、`production_default_changed=false`。

未验证：

- 两位复核者是同一模型家族的隔离运行，不是现实人类 annotator 或独立人工 reviewer；双 AI 一致候选不能升级为 human-gold，当前定向 human signed rows 仍为 `0`。
- Agent 仅依据工作包中的 URL 字符串判断，没有访问实时重定向或页面内容；复核集又是由候选规则的变化集筛选，存在选择偏差，不能外推到全部 references 或其他字段。
- 可选 profile 尚未成为生产默认，未用于重写当前 RQ1 统计、正式 RQ2 表格或论文主张；最终论文资格仍为 false。

下一步：

- 由现实人类 annotator 逐条复核这 `56` 条，交由独立 reviewer 复核并完成 author sign-off；保留证据和身份 provenance。
- 只有定向签收和门禁通过后，才考虑将 `resource_identity_v1` 切为默认，并重跑 RQ1/RQ2/COSE 全链路。
- 与此同时继续处理主复核包的 `236` 条正优先级记录，以及 affected_versions 和 cwe_ids 的独立验证；两套签收进度分别记录，不能把定向 `56` 条直接并入当前 `0/540` 统计。

### 17. 已实现并在权威远端运行：affected_versions 方法分歧双 AI 盲审与 contextual/package 消融

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/build_affected_versions_canonical_dual_review.py`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/affected_versions_canonical_dual_review_prompt.md`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_canonical_dual_review/worklist.blind.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_canonical_dual_review/worklist_manifest.json`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq3_affected_canonical_dual_review_agent_a.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq3_affected_canonical_dual_review_agent_b.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/merge_affected_versions_canonical_dual_review.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_canonical_dual_review/dual_ai_candidate.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_canonical_dual_review/dual_ai_review.json`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/evaluate_affected_versions_silver_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/test_affected_versions_semantic_baseline.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/analyze_affected_versions_contextual_variants.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_canonical_dual_review/contextual_variant_diagnostic.json`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_canonical_dual_review/contextual_variant_diagnostic.md`

验证：

- worklist builder 仅依据 raw/canonical 方法决策是否不同选择样本，共 `10/100` 条；输出去除 silver label/source、既有 expert candidate、方法预测与正确性字段。manifest 记录 `blinded_from_silver_labels=true`、`blinded_from_expert_candidate_labels=true`、`blinded_from_method_predictions=true`，worklist SHA-256 为 `317d9946ccc2419acc229d481cfdd8f912ce29a16e4e55bf63d1baf2ce872217`。
- 两个同模型家族 Agent 在彼此隔离、不读取项目其他标签/指标且不联网的条件下，分别对同一 `10` 条只读缓存证据进行裁决。Agent A/B 输出 SHA-256 分别为 `80003c2d771a5e324df314f422a2a8f6e822c97e40a351459de13429cbef6bfc` 和 `9149b302e399ec82f9f10fe602cf4d87ee356b2173edddbece9592501e226f6f`。
- 合并器逐行校验身份、完整 schema、枚举、布尔值、理由长度、证据 URL 可追溯性和低置信度复核要求；缺行、非法枚举、不可追溯 URL、low-confidence 却不要求复核四个负例均以退出码 `1` 被拒绝。
- contextual claim baseline 只接受目标 CVE 页面中靠近 affected/fixed 提示的版本 token，并排除已知 change-history、branch-selector 和 full-changelog 上下文；focused tests 覆盖 canonical alias、CVSS 假命中、旧 change-history、full changelog、无语义提示和缺目标 CVE。权威远端 `py_compile` 与 focused tests 通过。
- 已在权威远端对 `100` 条 affected_versions 样本运行 `12` 个 baseline，共生成 `1200` 条 silver 预测；随后重跑完整 AI candidate evaluator、canonical effect、contextual variant diagnostic、COSE table builder 和 package validator。
- COSE validator 保持 `submission_ready=false`；执行检查只剩远端缺少 ImageMagick `convert`，独立投稿阻塞仍包括 RQ2 canonical 空标签、RQ3 human final `0/180` 和投稿元数据占位符。

当前效果：

- 两个 Agent 对 `canonical_match_verdict` 与 `recommended_match_policy` 均为 `10/10` 一致、kappa `1.0`；adjudicated source 为 `7/10` 一致、kappa `0.5714`；discrepancy label 仅 `4/10` 一致、kappa `0.2308`；四个核心决策字段同时一致为 `4/10`，任一 Agent 要求追加复核为 `5/10`。
- 在 `7` 条来源共识上，raw token 命中 `4` 条、unrestricted canonical token `1` 条、contextual raw `1` 条、contextual canonical `2` 条、package-contextual raw `2` 条、package-contextual canonical `4` 条；既有 AI candidate 和 silver 也各命中 `4` 条。该集合是方法分歧定向样本，不代表总体分布。
- 全体 silver 上，raw/canonical token agreement 均为 `0.57`；contextual raw/canonical 分别为 `0.36/0.46`，coverage `0.70/0.80`；package-contextual raw/canonical 分别为 `0.18/0.21`，coverage `0.29/0.34`。
- 全体 AI candidate 上，raw/canonical token agreement 为 `0.46/0.49`；contextual raw/canonical 为 `0.39/0.49`，其中 canonical macro-F1 为 `0.3185`、coverage `0.80`；package-contextual raw/canonical 为 `0.24/0.30`，coverage `0.29/0.34`。
- 汇总诊断明确记录 `method_selection.status=unresolved_candidate_diagnostic_only`、`eligible_for_final_paper_claim=false`。当前证据支持把 canonical token 保留为候选特征，不支持把 token presence、context filter 或 package gate 单独选为完整版本范围裁决方法。

未验证：

- 两个 reviewer 仍是同一 AI 模型家族，不是现实人类 annotator/reviewer；所有新行均为 `label_is_human=false`，human signed rows 仍为 `0`。
- `10` 条由 raw/canonical 方法分歧选择，存在明显选择偏差；其 `4/7` 等计数不能外推到全部 `100` 条或 `652` 条 affected_versions FC。
- contextual cue 与页面角色仍是 lexical baseline，未覆盖跨生态版本规则、分支到模块的显式映射、发行版 backport、Git revision 或完整区间集合关系。
- silver/candidate 指标不能替代 human-gold；本轮没有切换最终方法、没有生成 human-gold 指标，也没有解除投稿门禁。

下一步：

- 将这 `10` 条方法分歧样本优先交给现实人类 annotator、独立 reviewer 与 author sign-off，尤其复核 Agent 在 label/source 上不一致的 `6` 条。
- 对 `100` 条 affected_versions audit 增加 package mapping、release branch、evidence-page role 和 range completeness 字段；签收后再按这些层次评估错误模式，而不是继续叠加字符串规则。
- 只有 signed audit 可用后，才比较 raw/canonical/contextual/package/range 方法的 coverage、selective risk 和分层结果，并决定论文主方法。

### 18. 已实现并在权威远端运行：CWE 4.20 taxonomy 消融与双 AI 盲审

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/external/cwe/cwec_v4.20.xml.zip`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_cwe_taxonomy_variants.py`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/cwe_taxonomy_dual_review_prompt.md`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_variant_diagnostic.{json,md}`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_changed_cases.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_dual_review_worklist.blind.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_cwe_taxonomy_dual_review_agent_{a,b}.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_cwe_taxonomy_dual_review.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_dual_ai_candidate.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/cwe_taxonomy/cwe_taxonomy_dual_ai_review.{json,md}`

验证：

- 权威远端下载并解析官方 CWE 4.20（日期 `2026-04-30`）Research Concepts `View_ID=1000`；归档 SHA-256 为 `3976f599e5e5200219a3108bb896d06e2a88fbb293369e1883cb423a5e9d7d50`，解析到 `969` 个 weakness 条目。
- taxonomy 变体只把“两个不相交集合中，每个 CWE 都有跨源 ancestor/descendant 覆盖”的 FC 改为 RD。全量 `8066` 条中，CWE 不相交 FC 为 `84` 条：full coverage `17`、partial coverage `3`、无 taxonomy relation `64`；变体只调整前 `17` 条，未修改生产 baseline。
- 候选/重复性分歧盲审 worklist 共 `15` 条，隐藏 baseline、primary candidate、review candidate 和 `taxonomy_v1` 标签，禁止联网；SHA-256 为 `b0e377429c321b7f789f6c079312aaf770d5abfec7698b0c74c8b52fb8b07fde`。
- 两个同模型家族 Agent 在彼此隔离的条件下分别完成 `15/15` 条。Agent A/B 输出 SHA-256 分别为 `8bca0799cf36dad0b179c933d26295a75fb7044114ff418223474e4dd389292d` 和 `61deb98a5cc075b2be88d3d10e08a6a4649b1051f21716e5acc6c86727d31599`。
- 合并器严格校验行数与顺序、身份、完整 schema、枚举、理由长度、官方 path 白名单和 low-confidence 复核要求；缺行、非法标签、未知 path、low-confidence 却不要求复核四个负例均以退出码 `1` 被拒绝。远端 `py_compile`、正式合并和输出行数检查通过。
- 已在权威远端重跑 `validate_cose_package.py --skip-latex-build`：退出码 `1`、`submission_ready=false`；唯一执行失败仍是缺少 ImageMagick `convert`，独立投稿阻塞仍为 RQ2 canonical 标签为空、RQ3 human final `0/180` 和投稿元数据/声明占位符。

当前效果：

- primary cwe_ids 的 determinate candidate agreement 从 current `45/49=0.9184` 变为 taxonomy_v1 `46/49=0.9388`，macro-F1 从 `0.8782` 到 `0.9123`；same-model review 则从 `12/12=1.0000` 降到 `11/12=0.9167`，macro-F1 从 `1.0000` 到 `0.9143`。两轮方向相反，不能据此选定方法。
- 两个 Agent 对 `set_relation` 和 `taxonomy_support_verdict` 均为 `15/15` 一致、kappa `1.0`；最终 `discrepancy_label` 为 `10/15` 一致、kappa `0.4898`；三个核心决策同时一致为 `10/15`，任一 Agent 要求追加复核为 `7/15`。
- taxonomy 支持判断的共同分布为：纯 granularity-only `1`、mixed `5`、不支持 granularity-only `9`。唯一纯层级共识是 `CVE-2024-1735` 的 `CWE-287` 与 `CWE-304`，官方路径为 `CWE-287>CWE-1390>CWE-303>CWE-304`；`CVE-2025-31724` 和 `CVE-2023-1625` 无官方路径，`CVE-2024-1300` 只有部分路径，均不能按纯层级差异处理。
- `15` 条盲审难例中只有 `1` 条属于 taxonomy_v1 实际影响的 `17` 条，且该条共识支持 taxonomy_v1；其余 `16` 条变更没有独立复核。汇总状态明确为 `method_selection.status=unresolved_candidate_diagnostic_only`、`production_default_changed=false`、`eligible_for_final_paper_claim=false`。

未验证：

- 两个 reviewer 仍是同一 AI 模型家族，不是现实人类 annotator/reviewer；所有新行均为 `label_is_human=false`，human signed rows 仍为 `0`。
- 盲审批次由 candidate 或 repeatability 分歧筛选，存在选择偏差；其中 `10/15`、`1/17` 等计数不能外推到全部 `8066` 条。
- 官方 CWE ancestor/descendant 关系只能证明两个类别在 taxonomy 中存在层级兼容，不能证明两个数据库对特定 CVE 的映射都正确，也不能替代漏洞上下文判断。
- 本轮没有修改 `scripts/build_field_discrepancies.py` 的生产默认，没有重写 RQ1/RQ2 正式表格，也没有生成 human-gold 指标或解除投稿门禁。

下一步：

- 对 taxonomy_v1 影响的 `17` 条候选逐条完成现实人类 annotator、独立 reviewer 与 author sign-off，优先复核尚未进入本轮盲审的 `16` 条。
- 对 mixed/partial-path 行保留组件级解释，不把部分 ancestor/descendant 关系提升为整组 RD；对无路径行继续依赖 CVE 上下文或 abstain。
- 只有 signed human-gold 可用后，才比较 current 与 taxonomy 变体的按字段 accuracy、macro-F1 和错误类型，并决定是否切换生产默认。

### 19. 已实现并在权威远端运行：RQ2/RQ3 AI-adjudicated gold 与统一诊断评估

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/ai_gold_adjudication_prompt.md`
- `/home/xiaoyuliang/code/vuln-adj/scripts/run_ai_gold_adjudication.py`
- `/home/xiaoyuliang/code/vuln-adj/scripts/import_interactive_ai_gold_adjudication.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/build_ai_adjudicated_gold.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/evaluate_rq2_ai_gold.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/evaluate_rq3_ai_gold.py`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/worklists/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/interactive_decisions/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/adjudication_passes/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/rq2_{primary,review}.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/rq3_{severity,affected_versions}.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/rq2/rq2_ai_gold_metrics.{json,md}`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/rq3/rq3_ai_gold_metrics.{json,md}`

验证：

- 所有新增 Python 脚本已在权威远端通过 `py_compile`；正式 worklist、裁决导入、全量快照构建和 RQ2/RQ3 评估均已实际运行。
- 主模型接口的小请求可达，但正式裁决返回 `insufficient_quota`；fallback 接口存在 TLS/proxy 连接失败。本轮没有伪造 API 输出，改为当前交互式 Codex 对风险工作集逐条复核，并记录 `model=codex_current_session`、`api_route=interactive_codex`、工作集/决策文件 SHA-256。
- RQ2 risk worklist 为 `53/300` 条，SHA-256 `d4b09f723d04dafdc20b4f2b95d5fa5974a15c37e8541f28d52e4c508eb5cfaa`；RQ3 severity 为 `51/80` 条，SHA-256 `16b254ef8a0b705986ad6cb60ab183ba7052125e867597d18fefb747331b0add`；RQ3 affected_versions 为 `96/100` 条，SHA-256 `c4cfed18099788c064c25eb2798d8fa3aecc53712096053b69858581d1bcaa17`。
- importer/build guard 的四个负例均被拒绝：风险行漏裁决、候选伪造 `label_is_human=true`、覆盖账本缺行、覆盖项修改 `sample_id`。
- RQ3 两个人工 evaluator 仍分别以退出码 `2` 拒绝 `0/80` 与 `0/100` final rows，未生成 human-gold metrics。
- 已重跑 severity/affected_versions baseline predictions、evidence-source reliability、COSE table builder 和 package validator；派生产物恢复 byte-identical。package validator 仍为退出码 `1`、`submission_ready=false`，唯一执行失败是缺少 ImageMagick `convert`，独立投稿阻塞未变化。

当前效果：

- RQ2 primary AI gold 共 `300` 条：`282` 条确定、`18` 条 uncertain；风险复核改动 `14` 个 discrepancy label，未改 RQ2 source 合同。current baseline 在确定子集为 accuracy `0.8972`、macro-F1 `0.9084`；reference candidate 为 `0.9291/0.9289`，CWE candidate 为 `0.9007/0.9118`，combined candidate 为 `0.9326/0.9323`。same-model consistency 为 `50/60=0.8333`、kappa `0.7923`。
- RQ3 severity AI gold 共 `80` 条，风险复核改动 `2` 个 label 和 `32` 个 source；`79` 条 final determinate、`1` 条 final abstain。evidence-score baseline 在确定子集为 accuracy `0.7215`、macro-F1 `0.7139`，gold coverage `0.9875`。
- RQ3 affected_versions AI gold 共 `100` 条，风险复核改动 `4` 个 label；`40` 条 final determinate、`60` 条 final abstain。canonical token 在确定子集为 accuracy `0.5000`、macro-F1 `0.2806`；raw token 为 `0.4750/0.2827`。package-gated raw token 为 accuracy `0.3500`、预测覆盖 `0.6500`、selective accuracy `0.5385`。没有方法对 `ghsa` 或 `neither` 类形成可靠覆盖。
- 所有 AI gold wrapper 与 metrics 均显式记录 `label_is_human=false`、`eligible_for_human_gold_claim=false`、`eligible_for_final_paper_claim=false`；production default 未切换。

未验证：

- 这些结果由同一模型家族的候选与风险复核构成，不是独立现实人类标注；现实人类签收仍为 `0/540`，不能称 human-gold，也不能作为最终论文主结果。
- RQ2 风险选择包含 baseline/candidate/repeatability 分歧，references/CWE 规则又由候选误差检查驱动，存在选择偏差和同源偏差。
- RQ3 severity 的 evidence baseline 与 AI gold 共享抓取证据；affected_versions 只有 `40%` gold coverage，确定子集指标不能外推到全部样本。
- affected_versions 的 package identity、release branch、backport 和完整 range semantics 仍未被现有 token/context/package baseline 充分建模；本轮没有选定最终方法。

下一步：

- 现实人类优先复核 RQ2 `18` 条 uncertain、RQ3 severity `22` 条 requires review 和 affected_versions `79` 条 requires review，并完成独立 reviewer 与 author sign-off。
- 在 signed human-gold 上重新评估 current/reference/CWE/combined 与 RQ3 全部方法；指标必须同时报告确定 gold coverage、预测 coverage 和 selective risk。
- affected_versions 下一轮方法工作应先补 package/release crosswalk 与范围语义证据，不继续把版本 token 命中堆叠成完整裁决器。
- 补齐投稿元数据和 ImageMagick 依赖；在人工金标、声明和复现门禁全部通过前保持 `submission_ready=false`。

### 20. 已实现并在权威远端运行：AI-gold 配对不确定性与 affected_versions 方法上限诊断

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/analyze_ai_gold_uncertainty.py`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/uncertainty/ai_gold_paired_uncertainty.json`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/uncertainty/ai_gold_paired_uncertainty.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/analyze_affected_versions_ai_gold_ceiling.py`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/affected_versions_ceiling/affected_versions_ai_gold_ceiling.json`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/affected_versions_ceiling/affected_versions_ai_gold_ceiling.md`

验证：

- 两个分析脚本均在权威远端通过 `py_compile` 并实际运行；不确定性分析固定 seed `20260715`，对每个配对比较执行 `10,000` 次按 AI-gold 标签分层的 paired percentile bootstrap。
- RQ2 使用 `282` 条 final-determinate AI-gold，RQ3 severity 使用 `79` 条，affected_versions 使用 `40` 条；每个比较同时记录 paired outcomes、accuracy/macro-F1/coverage/selective-accuracy 点估计及差值区间，exact McNemar 只标为 descriptive-only。
- affected_versions 上限分析读取相同 gold、`100` 条 evidence rows 和 `1200` 条方法预测；程序校验 `label_is_human=false`、`eligible_for_human_gold_claim=false`、样本 ID 全覆盖及五个选定方法逐样本完整性。
- 上限分析只使用结构化 `version_reasoning_type`、package profile、range relation 和 fetch profile；没有从 rationale 自由文本推断原因。输出中的 paired uncertainty SHA-256 固定为 `4ba94c70f6ad09e6b84634ff13617759a3d190a01d6aab0b36cb3c816613f1d6`。
- 已验证 cohort 行数为 `40 + 60 = 100`，逐行诊断为 `100` 条，五方法并集命中与漏判为 `23 + 17 = 40`；所有 final-paper/human-gold 资格字段为 false，production default 未改变。

当前效果：

- RQ2 current→reference accuracy 增量为 `+3.19pp`，95% bootstrap 区间 `[+1.42,+4.96]pp`，candidate-only `9`、baseline-only `0`；current→CWE 只有 `+0.35pp`，区间 `[0,+1.06]pp`，实际只新增命中 `1` 条；current→combined 为 `+3.55pp`，区间 `[+1.77,+5.67]pp`，新增 `10` 条中 `9` 条来自 reference。
- RQ3 severity prefer-NVD→evidence-score accuracy 增量为 `+40.51pp`，95% 区间 `[+30.38,+49.37]pp`；paired outcomes 为 candidate-only `44`、baseline-only `12`。这是共享证据条件下的 AI-gold 样本内优势，不是独立泛化结论。
- RQ3 affected_versions raw→canonical accuracy 增量 `+2.50pp`，区间 `[-10.00,+15.00]pp`；raw→contextual canonical 为 `-7.50pp`，区间 `[-20.00,+5.00]pp`；raw→package-gated raw 为 `-12.50pp`，区间 `[-22.50,-2.50]pp`，且 coverage 由 `0.975` 降到 `0.650`；package-gated raw 与 package-range 的预测和指标完全相同。没有候选比较同时满足正 accuracy 增量和区间下界大于 0。
- affected_versions 的 `100` 条 AI gold 中，显式 reasoning tag 为 package-identity `44`、range-semantic `43`、insufficient-evidence `12`、token-support `1`。`60` 条 final-abstain 中 package-identity 占 `40` 条，是数量最大的未决类别。
- `40` 条 final-determinate 中，canonical token 是最佳单方法，命中 `20/40=0.5000`；五个选定方法的事后并集只命中 `23/40=0.5750`，仍有 `17` 条被全部方法漏掉，且这 `17` 条全部带 `range_semantic` 标签。该 oracle 不是可部署选择器。
- raw/canonical 方法在 `60` 条 final-abstain 上仍分别输出非 abstain `58/60`；package-gated raw/package-range 降到 `19/60`。这些行没有确定目标，因此只能记录方法行为，不能计为错误或正确。

未验证：

- 所有区间都条件于当前 AI-adjudicated gold，不包含标注模型不确定性；RQ2 候选规则受误差分析驱动，RQ3 方法开发与裁决共享证据，不能把区间或 descriptive p 值解释为独立确认性推断。
- affected_versions 只有 `40%` gold coverage；事后并集使用真实标签选择正确方法，不可部署，也不能证明总体方法上限。
- `version_reasoning_type` 是 AI 裁决流程中的结构化标签；按标签观察到的错误集中不能解释为因果机制，仍需现实人类签收验证。
- 本轮没有新增 human-gold，现实人类签收仍为 `0/540`；没有切换 RQ2/RQ3 生产默认，也没有解除 COSE 投稿门禁。

下一步：

- affected_versions 暂停继续叠加词法 token 规则；优先构建可追溯的 NVD CPE/product ↔ GHSA ecosystem/package crosswalk，并明确无法映射时的 abstain 合同。
- 在 package identity 可比的样本上加入 release graph、分支、fixed/introduced 边界、backport 和集合关系证据；把区间语义与页面 token 支持分开建模。
- 冻结当前 `100` 条 audit 及开发/验证划分，由现实人类 annotator、独立 reviewer 与 author sign-off 后重跑 paired evaluation；同时报告 gold coverage、prediction coverage、selective accuracy 和预注册分层结果。
- RQ2 优先复核 reference 规则新增命中的 `9` 条及 CWE 唯一新增命中的 `1` 条，再在独立 holdout 上确认，避免把候选误差驱动的样本内增益写成最终贡献。

### 21. 已实现并在权威远端运行：affected_versions repository package crosswalk 候选

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/affected_versions_semantic_baseline.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/test_affected_versions_semantic_baseline.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/evaluate_affected_versions_silver_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/evaluate_rq3_human_audit.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/analyze_package_identity_crosswalk.py`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/package_identity_crosswalk/package_identity_crosswalk_diagnostic.{json,md}`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/uncertainty/ai_gold_paired_uncertainty.{json,md}`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/affected_versions_ceiling/affected_versions_ai_gold_ceiling.{json,md}`

验证：

- crosswalk 特征只读取 `nvd/ghsa_context.package_names` 和两侧 `references`，不读取 discrepancy label、adjudicated source 或其他 gold 字段；诊断产物显式记录 `crosswalk_built_from_gold=false` 和 `gold_fields_used_by_crosswalk=[]`。
- 规则只接受两侧包别名都能锚定同一非通用 GitHub repository 的桥接；`advisory-database`、`PoCs`、`CVEs` 等通用仓库被排除。若某侧还存在更匹配该包的独立仓库，则拒绝桥接，用于阻止 ImageMagick↔Magick.NET 一类 upstream/wrapper 误合并。
- focused tests 覆盖 Apiman 正向桥接、ImageMagick/Magick.NET 冲突拒绝、通用 PoC 拒绝和 Snyk vendor-prefix-only 拒绝；权威远端 `py_compile` 与测试均通过。
- 已在权威远端对 `100` 条 affected_versions 重新运行 `14` 个 baseline，共生成 `1400` 条预测；随后重跑 AI-gold evaluator、repository crosswalk 诊断、`10,000` 次配对 bootstrap 和七方法并集上限分析。
- crosswalk 诊断校验输入均为 `100` 条、四个目标方法逐样本完整、AI-gold provenance 为 false-human；新增方法已接入未来 guarded human-audit evaluator，但没有绕过 draft/final/reviewer 门禁。

当前效果：

- 现有 package-name gate 认为 `45/100` 条可比；repository crosswalk 新接受 `11` 条，使可比样本达到 `56/100`。这 `11` 条中 final-determinate `4`、final-abstain `7`；结构化 reasoning tag 为 package-identity `7`、range-semantic `2`、token-support `1`、insufficient-evidence `1`。
- Silver 上，raw crosswalk 相对 direct raw package gate：accuracy `0.32→0.39`、coverage `0.45→0.54`、selective accuracy `0.6222→0.6481`；canonical crosswalk 为 accuracy `0.39`、coverage `0.55`、selective accuracy `0.6364`。这些仍是 LLM silver 指标。
- 在 `40` 条 final-determinate AI-gold 上，raw crosswalk 相对 direct raw package gate：accuracy 均为 `0.3500`，coverage `0.6500→0.7250`，selective accuracy `0.5385→0.4828`；新增的 `3` 个非 abstain 决策均未命中 AI-gold 来源。
- Canonical crosswalk 相对 direct canonical package gate：accuracy `0.3250→0.3750`、coverage `0.6500→0.7500`，paired outcomes 为 candidate-only `2`、baseline-only `0`；accuracy 增量 `+5pp` 的 95% bootstrap 区间为 `[0,+12.5]pp`，仍不足以确认稳定改进。
- Crosswalk raw→canonical 的 accuracy 增量为 `+2.5pp`，区间 `[-7.5,+12.5]pp`。加入两种 crosswalk 方法后，七方法事后并集仍为 `23/40`，剩余 `17` 条全部是 range-semantic；crosswalk 解决了部分 package comparability，但没有突破范围来源裁决上限。

未验证：

- 候选方法族由既有 AI-gold 错误分析中的 package-identity 集中现象驱动，存在方法选择偏差；当前没有独立 holdout 或现实人类标签验证。
- 共同 repository 只提供项目身份候选，不能证明具体组件、发行分支或版本范围相同；当前 alias/冲突规则也未在全量 NVD-GHSA 上验证 precision/recall。
- `7` 条新映射仍为 final-abstain，没有确定 accuracy 目标；其方法输出只能记为行为，不能计为正确。
- 本轮未新增 human-gold，现实人类签收仍为 `0/540`；production default、COSE 主结果和投稿门禁均未改变。

下一步：

- 将 `11` 条新 repository bridge 逐条交给现实人类 annotator 和独立 reviewer，核对 package/component/repository 关系并冻结通过的映射；拒绝项也要保留证据。
- 对七方法共同漏判的 `17` 条 range-semantic 确定样本构建 release-graph/boundary 诊断，优先区分点版本、区间、分支、prerelease、backport 和 source-update timing。
- 新 range 方法必须在与这 `17` 条开发难例分离的冻结样本上评估，并同时报告 gold coverage、prediction coverage 和 selective accuracy。

### 22. 已修复并在权威远端重跑：affected_versions 输入完整性与冻结样本刷新

本次完成：

- 修复 `scripts/build_initial_corpus.py`：NVD configuration 中显式标记 `vulnerable=false` 的 CPE 不再进入 affected_versions 规范化视图
- 为 `scripts/build_annotation_samples.py` 增加 `--preserve-existing`，在刷新源上下文时固定已有 `sample_id`/CVE 映射并保留标注字段
- 增加 4 个聚焦测试，覆盖 false-CPE 过滤、正常 CPE 保留、冻结样本刷新和不再满足抽样条件时拒绝继续
- 在权威远端重建 initial corpus、field views/stats、Phase D 冻结样本，并复跑 affected_versions 证据、AI adjudication、AI-gold、silver、crosswalk、不确定性和七方法上限诊断
- 对 7 条受影响冻结样本逐条更新复核说明；所有行继续保持 `label_is_human=false`
- 扫描当前 GHSA reviewed snapshot，检查现有首 event/首 fixed 展平逻辑是否已遇到 multi-event range

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/build_initial_corpus.py`
- `/home/xiaoyuliang/code/vuln-adj/scripts/build_annotation_samples.py`
- `/home/xiaoyuliang/code/vuln-adj/scripts/test_build_initial_corpus.py`
- `/home/xiaoyuliang/code/vuln-adj/scripts/test_build_annotation_samples.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/input_integrity/analyze_affected_versions_input_integrity.py`
- `/home/xiaoyuliang/code/vuln-adj/results/input_integrity/affected_versions/affected_versions_input_integrity.json`
- `/home/xiaoyuliang/code/vuln-adj/results/input_integrity/affected_versions/affected_versions_input_integrity.md`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/discrepancies/field_discrepancy_stats.json`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/affected_versions_fc_manual_check.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/interactive_decisions/rq3_affected_versions_overrides.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/rq3/rq3_ai_gold_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/package_identity_crosswalk/package_identity_crosswalk_diagnostic.json`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/affected_versions_ceiling/affected_versions_ai_gold_ceiling.json`

验证：

- 权威远端系统 `python3` 的 `py_compile` 已通过；仓库 `.venv` 当前意外为 Python `3.6.8`，本次未将其结果作为验证依据
- `python3 scripts/test_build_initial_corpus.py` 与 `python3 scripts/test_build_annotation_samples.py`：共 4 个测试全部通过；包式 `python3 -m unittest scripts...` 因测试使用同目录导入而不适用
- initial corpus 实际重建：NVD `100,032`、GHSA `28,785`、matched pairs `8,066`
- `build_annotation_samples.py --preserve-existing` 已运行，100 条 affected_versions 样本的 ID/CVE 映射哈希保持为 `538c658683a3caec6d6faf9a2b66da064fafeb2b22e13580830c615330727a14`
- affected_versions AI-gold 已重建：`100` 行、`40` determinate、`60` abstain；决策账本中非空 label update 为 `0`
- RQ3 silver、AI-gold、repository crosswalk、配对区间和七方法事后并集诊断均已重跑，关键 affected_versions 指标未变
- COSE Markdown、表格和 RQ1 图已重建；package validator 的 claim-boundary lint 与生成结果字节一致性检查已通过

当前效果：

- 旧语料含 `1,105` 个 `vulnerable=false` CPE，涉及 `106/8,066` 条 matched rows；修复后剩余 `0`
- 全量 affected_versions baseline 有 `10` 条分类改变：`FC→RD 1`、`INC→EQ 1`、`INC→RD 6`、`RD→INC 2`
- 当前 affected_versions 分布为 EQ `425`、RD `3,936`、INC `3,054`、TD `0`、FC `651`
- RQ2 binary-different 由 `29,987` 变为 `29,986`，全字段 FC 由 `2,488` 变为 `2,487`
- 冻结的 100 条 affected_versions 样本中有 `7` 条源输入变化，其中 `2` 条为 final-determinate、`5` 条为 final-abstain；逐条复核后没有标签或来源决策变化
- severity evidence cache 当前为 470 URL records、415 个可用文本记录，`80/80` 样本有文本证据；affected_versions 仍为 585 URL records、401 个可用文本记录，`100/100` 样本有文本证据
- 当前 GHSA `28,785` 条 reviewed records 中 multi-event range 为 `0`；这只说明当前 snapshot 未触发该风险

未验证：

- 冻结样本复核仍是 AI adjudication，不是现实人类金标；human signed 仍为 `0/540`，RQ3 human final 仍为 `0/180`
- 当前 snapshot 未出现 multi-event range，不能证明未来 GHSA 数据可以安全展平；应增加输入 invariant 或保留完整 event 序列
- 输入修复没有改变当前 affected_versions AI-gold 指标，不等于 package identity、release boundary 或 range semantics 已解决
- 远端 `.venv` 的 Python 版本和依赖状态尚未修复；后续可复现环境需要单独处理
- COSE LaTeX rerender 仍缺 ImageMagick `convert`，且当前 TinyTeX 未提供可用的 `elsarticle.cls`；`status=fail`、`submission_ready=false`

下一步：

- 对七方法共同失败的 `17/40` 条 range-semantic 确定样本做 release-boundary 结构化诊断，区分 fixed/safe boundary、affected endpoint、分支和 backport
- 将诊断设计为独立 baseline/feature，不读取 gold 标签做预测；仅在评估阶段连接 AI-gold，并继续显式报告 `40%` gold coverage
- 启动现实人类复核与签收，不能用本次 AI recheck 替代 human-gold

### 23. 已实现并在权威远端运行：affected_versions release-boundary gold-blind 特征诊断

本次完成：

- 将 release-boundary 特征提取与 AI-gold 评估拆成两个阶段：特征阶段只读取 100 条缓存证据，不读取 gold；评估阶段才连接 AI-adjudicated gold
- 实现 CVE-local version claim role 抽取：affected/affected-endpoint、fixed boundary、introduced、safe exception
- 实现保守 token 对齐：精确、相同 release component 的 canonical equality、长 hash-bearing release token 前缀
- 对可解析区间检测“证据中的 fixed/safe release 落在来源声称的 affected span 内”这一边界冲突
- 增加 6 个聚焦测试，覆盖并行 fixed branch、Jenkins affected/fixed successor、同一 token 的 vulnerable/fixed 冲突、无 claim cue 拒判，以及 fixed/safe cue 不跨句绑定
- 对 40 条确定 AI-gold 运行独立评估、10,000 次按 gold source 分层的配对 bootstrap 和 exact paired test

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/affected_versions_release_boundary.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/extract_affected_versions_release_boundaries.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/test_affected_versions_release_boundary.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/evaluate_affected_versions_release_boundaries.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/release_boundary/affected_versions_release_boundary_features.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/release_boundary/affected_versions_release_boundary_features_summary.json`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/release_boundary/affected_versions_release_boundary_ai_gold_diagnostic.json`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/release_boundary/affected_versions_release_boundary_ai_gold_diagnostic.md`

验证：

- 权威远端系统 `python3` 的 `py_compile` 已通过
- `python3 experiments/rq3_adjudication/test_affected_versions_release_boundary.py`：6 个测试全部通过
- extractor 实际生成 `100/100` 条 feature rows；每行均有 `feature_extraction_uses_gold=false`，evaluator 对该 provenance 做强校验
- 100 条输出分布：`25 abstain`、`11 both`、`11 ghsa`、`13 neither`、`40 nvd`
- paired bootstrap 使用 `10,000` 次、seed `20260715`、按 AI-gold source 分层

当前效果：

- unrestricted canonical token reference：`20/40`，accuracy `0.5000`，coverage `1.0`
- release-boundary：`22/40`，accuracy `0.5500`，coverage `0.9500`，selective accuracy `0.5789`
- 固定 boundary→crosswalk canonical fallback：`23/40`，accuracy `0.5750`，coverage `1.0`
- hybrid 相对 canonical token 的增量为 `+7.50pp`，95% percentile interval `[-12.50,+27.50]pp`；`14` 个改进、`11` 个回退、exact paired two-sided `p=0.6900`
- release-boundary 命中旧七方法共同失败的 `11/17`；事后方法并集由 `23/40` 提高到 `34/40`
- 句界 cue binding 修正后，`058` 的预发布边界不再被相邻 CVSS 文本抑制；当前结果说明 boundary role 提供了与 token/package 方法不同的互补信号，但固定组合尚未形成稳定净增益

未验证：

- 特征提取虽不读 gold，但实验方向是在检查旧共同失败样本后选定，属于 post-hoc exploratory diagnostic
- gold 仍是 AI-adjudicated，只有 `40/100` 条确定；60 条 final abstain 没有 accuracy target，现实人类 final 仍为 `0/100`
- 事后 `34/40` 并集不是可部署 selector；不能把 oracle coverage 写成方法性能
- lexical claim roles 不是完整 release graph，尚未稳定处理并行维护分支、pre-release qualifier 丢失、exception、backport、开放上界和证据修订时序
- production defaults 未改变

下一步：

- 对剩余 6 条旧共同失败样本分别落盘结构化需求：多分支 fixed 集合、pre-release 序、开放上界、exception 与证据修订时序
- branch/release-graph 候选实现与本轮 AI-gold 诊断见下一节；后续必须冻结新 holdout，避免继续围绕这 40 条调规则
- 启动现实人类签收；在 human-gold 完成前，release-boundary 只能作为候选特征

### 24. 已实现并在权威远端运行：affected_versions branch/release-graph gold-blind 候选

本次完成：

- 在 release-boundary 之上新增三类保守结构事件：不透明版本 leading numeric ordinal 范围中的 safe exception、相邻 pre-release fixed boundary、明确 affected endpoint 对开放 affected span 的冲突
- 特征提取阶段只读取 100 条 evidence rows 和来源值，不读取 gold；AI-gold 只在独立 evaluator 中连接
- 为所有 100 条样本输出 fixed-set branch coverage、跨 host fixed-boundary 冲突、无目标 CVE 文本的已抓取链接记录和 NVD modified-after-enrichment 等能力缺口
- 对上一轮 6 条残余共同误例逐条复核；只把可泛化的 `037/040/069` 三类结构写入预测，`043/052/065` 保留为来源冲突、快照更新或证据时序缺口

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/affected_versions_branch_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/extract_affected_versions_branch_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/test_affected_versions_branch_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/evaluate_affected_versions_branch_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/branch_graph/affected_versions_branch_graph_features.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/branch_graph/affected_versions_branch_graph_features_summary.json`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/branch_graph/affected_versions_branch_graph_ai_gold_diagnostic.json`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/branch_graph/affected_versions_branch_graph_ai_gold_diagnostic.md`

验证：

- 权威远端系统 `python3 -m py_compile` 对 release-boundary 与 branch-graph 的 8 个脚本全部通过
- 原 release-boundary 6 个测试和新增 branch-graph 5 个测试全部通过
- extractor 生成 `100/100` 条 feature rows，全部为 `feature_extraction_uses_gold=false`；evaluator 校验 100 条 feature/gold ID 一致、AI provenance 和两种 fallback 全覆盖
- 全部 100 条中只改变 4 条 release-boundary 预测：`037 nvd→neither`、`040 abstain→ghsa`、`043 nvd→neither`、`069 both→nvd`
- branch-graph 的 100 条预测分布为 `24 abstain`、`10 both`、`12 ghsa`、`15 neither`、`39 nvd`

当前效果：

- branch/release-graph 单独在 40 条确定 AI-gold 上命中 `25/40`，accuracy `0.6250`，coverage `0.9750`，selective accuracy `0.6410`
- 固定 branch-graph→crosswalk canonical fallback 命中 `26/40`，accuracy `0.6500`，coverage `1.0`
- 相对 release-boundary fallback 增量为 `+7.50pp`，95% percentile interval `[0,+15.00]pp`；`3` 个改进、`0` 个回退、exact paired two-sided `p=0.2500`
- 相对 unrestricted canonical token 增量为 `+15.00pp`，区间 `[-5.00,+35.00]pp`；`17` 个改进、`11` 个回退、exact `p=0.3449`
- branch-graph 命中旧七方法共同失败的 `14/17`；事后方法并集由 `23/40` 提高到 `37/40`
- 剩余 3 条共同误例为 `043/052/065`：分别涉及跨来源 fixed boundary 冲突、GHSA 快照/多分支 fixed 集合不一致、以及 modified-after-enrichment 与补丁落地时序；当前没有足够的 gold-blind 结构证据稳定选择 GHSA

未验证：

- 三类规则是在检查上一轮残余误例后设计，仍是 post-hoc exploratory candidate；`[0,+15]pp` 包含边界 0，exact test 也不支持确认性结论
- opaque ordinal 只比较 leading numeric component，不构成 Jenkins 等生态的完整版本序
- 74/100 条样本至少有一条已抓取链接记录不含目标 CVE 文本，62/100 条含 modified-after-enrichment 页面；这些 flag 只表示证据/时序风险，不证明来源错误
- source authority、temporal revision、多分支 snapshot repair、backport 和 ecosystem-specific ordering 尚未实现
- gold 仍为 AI-adjudicated，只有 `40/100` 条确定；human final 仍为 `0/100`，production defaults 未改变

下一步：

- 冻结未参与本轮规则诊断的新 holdout，在 holdout 上独立复现 `037/040/069` 三类结构事件的净效果
- 为 `043/052/065` 分别补来源权威/发布时间、完整多分支 fixed-set 和补丁落地时序证据；证据不足时继续 abstain，不按当前 gold 硬编码
- 启动现实人类签收，并在 human-gold evaluator 中重新比较 canonical、release-boundary 与 branch-graph 候选

### 25. 已实现并在权威远端运行：affected_versions 严格双 Agent source re-audit 与 overlay 诊断

本次完成：

- 再次扫描本地与权威远端仓库叙事，未发现任何废弃主机、用户目录或跳板地址；当前实验统一在 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj` 运行
- 审计原 affected_versions AI-gold 状态，确认 `final_abstain` 同时混合“差异标签不确定”和“来源证据不足”；60 条 final-abstain 中有 45 条保存了非 abstain source suggestion，不能直接当作确定 source
- 为这 45 条生成固定 selection manifest，在隔离 cache 中刷新 234 个 URL，不修改冻结的 100 条主 evidence artifact
- 启动两个互不可见的 Codex Agent：Agent A 按 evidence-first 合同复核，Agent B 按 skeptical 合同复核；二者均不得调用外部 LLM，也不得把抓取失败或缺失文本当作反证
- 实现 source re-audit 合并器、严格合同测试、overlay evaluator、证据刷新统计和 branch failure analyzer

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions/selection_manifest.json`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions/evidence_refresh/source_rows.evidence.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions/agent_a_decisions.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions/agent_b_decisions.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/build_affected_versions_source_reaudit_inputs.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/merge_affected_versions_source_reaudit.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/evaluate_affected_versions_source_overlay.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/test_merge_affected_versions_source_reaudit.py`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/source_reaudit/affected_versions_source_reaudit_consensus_summary.json`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/source_reaudit/rq3_affected_versions_source_gold_overlay.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/source_reaudit/affected_versions_source_overlay_diagnostic.json`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/source_reaudit/affected_versions_source_overlay_branch_failures.json`

验证：

- 权威远端系统 `python3` 对 6 个新脚本通过 `py_compile`；source merge 的 4 个正负合同测试全部通过
- 固定选择恰好为 45 条；刷新前可用 URL records 为 `157`，刷新后为 `214`，`26/45` 条样本获得新增可用证据，丢失可用证据为 `0`
- 主接口返回 `insufficient_quota`，fallback 接口发生 TLS `UNEXPECTED_EOF`；两个接口均未产生裁决行，未把失败调用计入任何结果
- Agent A 输出 `45` 行：`4 both`、`41 abstain`；Agent B 输出 `45` 行：`10 both`、`1 nvd`、`1 ghsa`、`1 neither`、`32 abstain`。decision SHA-256 分别为 `559d798aa21ae4633df1d11d0cba97e08a570e9210099e0bb5bbd5c12499bf4a` 和 `8191f9301358ff1e22cbfed12f10acd66b075208e9d028952997460639756801`
- 所有 Agent、consensus 与 overlay 行均保持 `label_is_human=false`；原 AI-gold 和冻结 evidence 文件没有被覆盖

当前效果：

- 两个 Agent source decision 精确一致 `36/45=0.8000`，Cohen's kappa（含 abstain）为 `0.3982`
- 严格合并只接受 4 条 exact non-abstain 且非 low-confidence 的一致裁决，四条均为 `both`；source overlay 确定覆盖由 `40/100` 增加到 `44/100`
- 原 40 条 cohort 保持不变：canonical token `20/40`，release fallback `23/40`，branch fallback `26/40`
- 新增 4 条 cohort：canonical token `4/4`；release-boundary 与 branch/release-graph 的 raw/fallback 均为 `0/4`
- 合并 44 条：canonical token `24/44=0.5455`，release fallback `23/44=0.5227`，branch fallback `26/44=0.5909`。branch 相对 canonical 的差值为 `+4.55pp`，95% percentile interval `[-13.64,+22.73]pp`，`17` 个改进、`15` 个回退、exact paired two-sided `p=0.8601`
- 四条新增失败都属于 `no_package_name_overlap`。现有 crosswalk/branch graph 因共享 CVE 或 repository 将不同 artifact 的版本范围放入同一 release space，进而产生错误的 `neither` 或 abstain；一个只针对这四条的 direct-package router 在原 40 条上退化，未作为方法落盘

未验证：

- 两个 reviewer 都是 Codex Agent，不是现实人类 annotator/reviewer；overlay 不是 human-gold，现实人类签收仍为 `0/540`，RQ3 human final 仍为 `0/180`
- 原 40 条确定 source 没有按本轮严格双 Agent 合同重跑；因此 44 条 overlay 的来源过程不完全同质
- 新增 4 条来自 prior-abstain 且证据足以形成双 Agent 共识的选择性子集，不是随机 holdout；`4/4` 与 `0/4` 只能暴露失败机制，不能估计总体性能
- dedicated evidence refresh 改善了可读性，但没有证明证据权威性、时间一致性或 artifact 映射正确
- production default、COSE 主结果和投稿门禁均未改变

下一步：

- 不针对四条样本增加特例；先实现 evidence-bound artifact identity，并为 NVD 与 GHSA 分别维护 release graph，只有证据证明 artifact 可比较时才做区间关系判断
- 将原 40 条按同一严格双 Agent source 合同重跑，或冻结新的独立样本，避免混合裁决流程后直接比较
- 现实人类优先签收新增 4 条和 9 条 Agent disagreement，再在统一 human-gold 上重评 canonical、release-boundary 与 branch-graph

### 26. 已实现并在权威远端运行：affected_versions 统一严格 source overlay、artifact-bound v2 与同证据方法对比

本次完成：

- 将原 `40` 条 `final_determinate` 样本作为独立 cohort，使用与 prior-abstain re-audit 相同的正证据合同重新生成 selection、刷新证据，并启动两个新的隔离 Codex Agent 独立复核
- 扩展 source re-audit builder、evidence refresh analyzer 和 merge contract，使原 40 条可按 `replace_with_strict_consensus` 重建；未覆盖冻结 AI-gold 主文件
- 将原 40 条严格接受行与 prior-abstain 严格新增 4 条合并为统一严格 source overlay；其余行显式 abstain
- 实现 artifact-bound v2：只有两个来源各自的 CVE-scoped record 同时包含来源专属 artifact alias 和正 version-token support 时，才将 branch `abstain/neither` 改为 `both`；不覆盖一侧来源判断
- 构建 selection-aware 统一 evidence overlay，在同一证据输入下重跑 `14` 个既有 baseline、branch graph、artifact-bound v2 及固定 fallback，并生成全方法排序、证据快照稳定性和 residual failure worklist

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions_determinate/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/ai_adjudicated_gold/source_reaudit/rq3_affected_versions/evidence_overlay_uniform/`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/affected_versions_artifact_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/extract_affected_versions_artifact_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/test_affected_versions_artifact_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/build_affected_versions_source_evidence_overlay.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/evaluate_affected_versions_artifact_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/analyze_artifact_graph_evidence_snapshot_stability.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/analyze_artifact_graph_uniform_strict_failures.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/ai_adjudicated_gold/evaluate_affected_versions_uniform_strict_methods.py`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/source_reaudit/determinate_reaudit/`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/source_reaudit/uniform_strict/`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/artifact_graph_snapshot_stability/`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/artifact_graph_uniform_strict/`
- `/home/xiaoyuliang/code/vuln-adj/results/ai_adjudicated_gold/artifact_graph_uniform_strict_same_evidence/`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/uniform_evidence_baselines/`

验证：

- 原 40 条 selection 恰好为 `40` 行；刷新 `234` 个 URL 后，可用 records 从 `160` 增至 `224`，`20/40` 行获得新增可用证据，`1` 行从 6 个降为 5 个可用记录
- Agent A 最终输出为 `31` 条 determinate、`9` 条 abstain；原输出因 `unresolved` 字段误用 list 被 merge contract 拒绝，恢复后只做 list-to-string 格式转换。最终 SHA-256 为 `3d12431beb5f35080ce81a6008630714e9a36793f0a889c7c4bcaa855b0e2af8`
- Agent B 输出为 `38` 条 determinate、`2` 条 abstain，SHA-256 为 `88164917b5288c035109755b9b3bae6170d7ccc62d4a22af4dbf57c3fec3df2d`。Agent B 披露 schema 检查时首条完整 candidate object 可见；虽声明未把 prior source 当证据，仍不声称完美盲审
- 原 40 条 source decision 精确一致 `29/40=0.7250`，Cohen's kappa（含 abstain）为 `0.6502`；严格接受 `27/40`：`8 both`、`9 ghsa`、`2 neither`、`8 nvd`
- 统一严格 overlay SHA-256 为 `6c8d6a5765cfa9da346ade83cfc6e235de5a807fff1b3987c87bc37c342666b5`；共 `31/100` determinate，分布为 `12 both`、`9 ghsa`、`2 neither`、`8 nvd`
- artifact-bound v2 的 6 个 focused tests 全部通过；统一 evidence overlay、artifact features 的 SHA-256 分别为 `53908116d26d999007e01b1b07cd0b0a78d4338d884df1c84aa51fb579d2a32e`、`6dc4136e3ca56f9fac0e95895aac1640177d2b2e12aa3e09cd0ca68b8a589e18`
- Agent、consensus、overlay 和 benchmark 均保持 `label_is_human=false`；没有写入 human annotator/reviewer 字段，没有改变 production default

当前效果：

- 原 40 条中有两条严格 source 反转：`029` 从 `both` 改为 `nvd`，`092` 从 `nvd` 改为 `ghsa`；另有 `11` 条 Agent 分歧和 `2` 条 exact low-confidence abstain 未进入 overlay
- prior-abstain 新增 4 条上 artifact v2 为 `4/4`，说明 artifact binding 能修复该定向失败；但同一证据输入的统一 31 行上，artifact v2 为 `16/31=0.5161`，低于 raw token `18/31=0.5806` 和 canonical token `17/31=0.5484`，branch graph 为 `12/31=0.3871`
- full-coverage 当前最高为 raw token `18/31`；raw 相对 canonical 仅多 1 个命中、0 个回退，差值 `+3.23pp`，95% interval `[0,+9.68]pp`，exact `p=1.0`
- selective 最高为 package-range 与 package-gated token 并列：`12/19=0.6316`，prediction coverage `19/31=0.6129`；不能脱离 coverage 与 full accuracy 单独报告
- 统一证据刷新使 branch raw 预测改变 `15/100`；在旧 44 行 cohort 上，branch fallback 从 `26` 个命中降至 `19` 个，artifact fallback 从 `30` 个降至 `23` 个，说明方法对页面/证据快照敏感
- 统一 31 行上 canonical-only correct 为 `10`、artifact-only correct 为 `9`、两者共同正确为 `7`；共同失败 `5` 条中 `4` 条 gold 为 `ghsa`，当前缺口集中在 source authority、temporal revision 和 package-local structured range interpretation

未验证：

- 两轮 reviewer 都是 Codex Agent，不是现实人类 annotator/reviewer；统一 overlay 不是 human-gold，现实人类签收仍为 `0/540`，RQ3 human final 仍为 `0/180`
- 原 40 条和 prior-abstain 45 条虽使用相同决策合同，但选择都受 prior AI-gold 状态影响；统一 evidence refresh 也不是随机、独立采样
- artifact v2 是检查 strict-addition failures 后设计的 development-coupled 规则；其 `4/4` 不能解释为总体泛化性能
- 当前 `31/100` 覆盖过低，且 source 分布不均；现有 accuracy、bootstrap interval 和 exact test 都只能作为样本内探索性诊断
- 证据刷新记录的是可抓取文本快照，不证明来源权威性、发布时间因果关系、artifact 映射或版本范围语义正确

下一步：

- 现实人类优先签收统一严格 31 条、两条 source 反转和 11 条 Agent 分歧；未签收前不把 Codex overlay 改写为 human-gold
- 冻结未参与 re-audit selection 和 artifact 规则设计的新 holdout；在冻结证据快照上预注册主要方法、coverage 与 paired comparison
- 不增加样本特例；实现 package-local structured range parser，并显式建模 source authority、temporal revision、多分支/backport 和 ecosystem-specific ordering
- 将 5 条共同失败作为能力需求 worklist，而不是直接生成规则；新能力先用单元测试验证，再在独立 holdout 评估净效果

### 27. 已实现并在权威远端运行：affected_versions CVE-disjoint holdout、预测预密封与双 Codex 严格裁决

本次完成：

- 启动两个只读审计 Agent，分别检查新 holdout 的采样边界和证据/裁决泄漏；确认现有 Phase D sampler 无排除集、旧 source re-audit 依赖 prior AI-gold、silver evaluator 会把标签写入预测文件，均不能原样用于独立评估
- 新增 development-disjoint holdout builder：从当前 `651` 条 affected_versions factual-conflict 候选中按 CVE/NVD/GHSA identity 排除完整旧开发集 `100` 条，在剩余 `551` 条中按固定 SHA-256 rank 冻结 `100` 条
- 使用全新专用 cache 抓取全部 holdout 引用，不复用默认 evidence cache；再通过字段 allowlist 生成无 baseline/gold/candidate/prediction 字段的盲 worklist
- 新增 prediction-only runner，在任何 Agent 决策文件存在前密封 `18` 个方法、`1800` 条无标签预测及 graph features；预注册 primary 为 raw token，指标为 strict all-row source accuracy，并冻结方法代码哈希
- 启动两个全新、无旧任务上下文的隔离 Codex Agent；A 按 evidence-first、B 按 skeptical 合同独立复核全部 100 条，禁止读取旧 gold、候选、预测和另一 Agent 输出
- 新增 discrepancy+source 联合严格 merge：只有两个 Agent 的差异类型和来源均精确一致、双方 determinate、非 low-confidence，且正支持/反证 URL 均来自可用冻结证据时才接受
- 按预注册协议运行 all-strict 方法评估；揭封后发现 task mixing，另以 `analysis_is_posthoc=true` 运行 FC-only/non-FC 分层，不改 sealed 方法或 primary 输出

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/build_affected_versions_holdout.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/build_affected_versions_blind_worklist.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/predict_affected_versions_holdout.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/merge_affected_versions_holdout_adjudication.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/evaluate_affected_versions_holdout.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/analyze_affected_versions_holdout_composition.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/analyze_affected_versions_holdout_task_split.py`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/affected_versions_holdout_adjudication.md`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/affected_versions_v1/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/affected_versions_v1/`
- `/home/xiaoyuliang/code/vuln-adj/paper/cose/sections/{01_introduction,03_method,04_experimental_setup,05_results,06_discussion,07_threats_to_validity,09_conclusion}.md`
- `/home/xiaoyuliang/code/vuln-adj/paper/cose/full_draft.md`
- `/home/xiaoyuliang/code/vuln-adj/results/paper_cose/cose_package_manifest.json`

验证：

- 权威远端为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）；holdout builder 的 6 个测试、盲 worklist 的 2 个测试、strict merge 的 4 个测试全部通过
- 全量 FC、旧排除集、eligible、holdout 行数为 `651/100/551/100`；CVE、NVD ID、GHSA ID 与 identity tuple 均唯一，holdout 与旧 100 条在这些 identity 上交集均为 0
- 冻结 CVE commitment 为 `8ae0a8d60e5ec6dac9a8296fa8df966aae85dbc86d924a142824f6be9e006213`；source rows SHA-256 为 `e31842c1560b7247e88c4bbf81ee4c6477a59476304ee22fd8e3d6466ee987b9`
- 568 个 evidence records 中 `540 ok`、`15 timeout`、`8 http_403`、`2 http_404`、`3 url_error`；`538` 个记录有可用正文，`100/100` 行至少有一个可用记录。冻结 evidence SHA-256 为 `d437bb7f69408aacea27bf7766ab94ff14566c083c2afb62abbc6b238fc9bacd`
- blind worklist SHA-256 为 `043062e52d283c3ec5e25d2a598ed65ac311c6b1d380f822e1489328352e5083`；逐层扫描没有 baseline/annotation/candidate/gold/prediction/silver key
- sealed predictions SHA-256 为 `72315933bac69a20b542b9eabe70fa445617e009f7a963eb309ec26e60f7d7d2`；共 100×18=`1800` 条唯一 sample/method，未含 gold/silver/is_correct 字段。主流程确认两个 Agent 文件当时均不存在，且随后两个 decision 文件 mtime 均晚于 seal
- Agent A/B 均为 `100/100` 合同通过、`label_is_human=false`。A 为 `78` determinate/`22` abstain，SHA-256 `b3b1c08637a089d21abf2252ce87e33046c9141f318718b0b69471faabcabd24`；B 为 `43/57`，SHA-256 `8c0e2c17d886071f3aad40557210c3d470dc6b8b704aae8d802b3c18aca0c400`
- 已将 holdout 协议、双 Agent 一致性、all-strict 结果和 post-hoc FC-only 边界写入论文源，并在权威远端成功重建 `paper/cose/full_draft.md`。`validate_cose_package.py --skip-latex-build` 的 silver/affected_versions claim-boundary lint 已通过；投稿包仍为 `submission_ready=false`，执行阻塞仅保留远端缺少 ImageMagick `convert` 以及未刷新 LaTeX 日志中的 fatal 标记，因此不能写成 LaTeX 已重建或投稿包已通过

当前效果：

- discrepancy label 精确一致 `42/100`、kappa `0.2679`；source 精确一致 `53/100`、kappa `0.3919`；联合一致 `42/100`，其中只有 `35` 条满足严格 determinate 合同，coverage `0.35`
- 严格 35 条的标签为 `16 factual_conflict`、`17 representation_discrepancy`、`2 incomplete`；来源为 `17 both`、`7 ghsa`、`7 nvd`、`4 neither`
- 预注册 all-strict 排名：branch fallback 与 artifact fallback 均为 `17/35=0.4857`；canonical/contextual 为 `16/35=0.4571`；raw、branch raw、artifact raw 均为 `15/35=0.4286`。该结果条件于 35% strict coverage
- post-hoc task split 发现 all-strict 指标混合了两个任务：17 条 RD 全部 gold source=`both`，使偏向 `both` 的 token 方法在非冲突子集达到 raw `14/19`、canonical `15/19`
- 真正 FC 的 16 条来源分布为 `7 ghsa`、`5 nvd`、`4 neither`，没有 `both`。FC-only 上 branch/artifact raw/fallback、prefer-GHSA 和 latest-published 均为 `7/16=0.4375`；branch/artifact raw selective accuracy 为 `7/13=0.5385`、prediction coverage `13/16=0.8125`；raw/canonical 仅 `1/16=0.0625`
- 因此现有 evidence/graph 方法在真正 FC 上没有超过固定 GHSA 或 recency baseline；旧 all-strict token 高分主要反映非冲突识别，不能解释为来源裁决能力

未验证：

- 两位 reviewer 都是 Codex Agent，不是现实人类 annotator/reviewer；所有 holdout 产物均为 false-human expert candidate，现实人类签收仍为 `0/540`，RQ3 human final 仍为 `0/180`
- 新 holdout 对旧方法开发是 CVE-disjoint，但仍由已经过开发的 deterministic FC candidate miner 选出，不能支持 candidate generation 的总体独立泛化结论
- strict coverage 只有 `35%`，label/source kappa 较低；65 条分歧/拒判不能静默排除，当前 16 条 FC 也不足以做确认性显著性推断
- FC-only endpoint 是揭封后发现的协议修正，因此只能作 post-hoc 诊断；本 holdout 已揭封，不能再用于调参后的独立验证
- 证据抓取成功不等于来源权威、artifact 对齐或版本边界正确；双 Agent 分布差异说明裁决合同仍需现实专家校准

下一步：

- 现实人类复核新 holdout 全部 100 条，优先签收 35 条联合候选并裁决 65 条 disagreement/abstain；不得把 Codex consensus 复制为 human 字段
- 将 discrepancy typing 与 FC-only source adjudication 分为两个预注册 endpoint；同时报告 candidate precision、strict/human coverage、source accuracy、prediction coverage 和 selective accuracy
- 当前 holdout 只保留作固定 benchmark；在开发集实现 package-local structured range parser、source authority、temporal revision、多分支/backport 后，冻结新的 v2 CVE-disjoint holdout
- affected_versions 方法贡献暂不成立；论文当前可保留可审计流水线、拒判机制、artifact/snapshot threat 和 task-mixing protocol finding

### 28. 已实现并在权威远端运行：affected_versions v2 双端点封存评估

本次完成：

- 在两个只读协议审计 Agent 对比后，修复 reviewer 文件独立性、blind manifest 真实绑定、输入顺序、structured literal-quote evidence、artifact/type compatibility、type/source endpoint 分离、abstain 计分和封存代码哈希门禁
- 从当前 `651` 条 deterministic FC candidates 中排除 Phase D 和 v1 holdout 共 `200` 个 CVE，在剩余 `451` 条中按固定 SHA-256 rank 冻结 v2 `100` 条；主流程未检查被选行的字段值
- 使用专用 evidence cache 生成 `564` 条冻结证据和递归 key-scan blind worklist；100/100 行至少有一条可用文本记录
- 仅使用已揭封 Phase D/v1 做 post-hoc method development，冻结 package-local task-separated type head；FC source endpoint 使用独立运行的既有 `branch_release_graph`，未把同一实现重新命名为新方法
- 在 reviewer 文件不存在时一次性封存 3 个 type methods 的 `300` 条预测和 19 个 source methods 的 `1,900` 条预测，同时记录 method/protocol code hashes
- 启动两个全新、无历史上下文的 Codex reviewer；A 按 evidence-first、B 按 artifact/scope-first 合同，只读 prompt 与 blind worklist，独立完成 100 条并写入不同文件
- 按冻结合同分开 merge type consensus 与 FC-source consensus，再按预注册 full accuracy（abstain 计错）、coverage、selective accuracy 和 paired bootstrap 运行 evaluator；揭封后没有修改方法或端点

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/build_affected_versions_holdout_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/build_affected_versions_blind_worklist_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/seal_affected_versions_holdout_v2_predictions.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/merge_affected_versions_holdout_v2_adjudication.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/evaluate_affected_versions_holdout_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/affected_versions_task_separated.py`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/affected_versions_holdout_v2_adjudication.md`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/affected_versions_v2/`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/affected_versions_v2/`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_task_separated/`

验证：

- 权威远端确认为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）；远端 `python3 -m unittest discover -s experiments/holdout -p 'test_*.py'` 为 `34/34` 通过，task-separated focused tests 为 `9/9` 通过
- eligible/selected 为 `451/100`；v2 与 Phase D、v1 在 CVE/NVD/GHSA identity 上均零重叠。source rows SHA-256 为 `2397dc9991025c82953092d010683fba1087e614af8477696db9eda3cc182e55`，CVE commitment 为 `dcb97b753c2b94981e224ecd5b10f43641a60f56a39f5795141120b52bd440fc`
- evidence SHA-256 为 `a32932c14b18e289e6f3098e49982ce1c99628557d63539bdef7578784599560`；`537` 条为 `fetch_status=ok` 且有文本，其余为 `11 timeout`、`9 http_403`、`1 http_404`、`5 url_error`、`1 skipped_non_text`
- blind worklist SHA-256 为 `c5d510d51ccd2bc007a43e812bac1d2646eebc5c428c95c079dc2202938bea58`；递归扫描确认不含 label/method/prior candidate keys
- 封存前两个 reviewer 文件和三个 sealed output 均不存在。sealed type/source SHA-256 分别为 `b665e8086a91426d687902a7e1ab2bd45e120c40363d169a1041b915ccaa98ee`、`bdcd37f63302e228287296890ae9ec527e0314598f00fad17eb2887f1f636f26`
- Agent A/B 最终 SHA-256 分别为 `8141f9007196e61199477fa88b1932724d0c920ceb7a783464c8accd1fc729ff`、`d427a0187530651d8ee589cf959d7c8a8ef6367399ae5e0adcfc56366e3d01a1`；文件路径、内容、reviewer/run ID 均不同，顺序和 100 行覆盖与 blind input 一致
- merge 与 evaluator 均通过封存 hash/mtime gate。consensus SHA-256 为 `14563acaf800036ab8c573cb0111912986a5eda3d072334ec5d10afc215bf39f`；evaluation SHA-256 为 `4b5bc1a3d09851ad8b2049169f999462cab3aea865678b76bdb99df1fa2ff1e2`
- 已在权威远端重建 `paper/cose/full_draft.md`；`validate_cose_package.py --skip-latex-build` 的 silver/affected_versions claim-boundary lint 已通过。package 仍为 `submission_ready=false`，失败项只剩远端缺少 ImageMagick `convert` 导致 rerender 失败，以及尚未刷新的 LaTeX fatal/emergency-stop 日志

当前效果：

- discrepancy label 精确一致 `65/100`，artifact relation 精确一致 `80/100`；kappa 分别为 `0.5353`、`0.6690`
- strict type consensus 为 `41/100`，标签分布为 `15 FC`、`8 INC`、`18 RD`；这再次表明 deterministic FC candidate miner 中大量行不是双 reviewer 支持的 factual conflict
- 15 条 strict FC 中，source 精确且 determinate 一致为 `9/15`，source kappa `0.4079`；严格来源分布为 `6 nvd`、`1 ghsa`、`2 neither`。相对全 cohort 的 strict FC-source coverage 只有 `9%`
- 预注册 type primary `task_separated_type_v1` 在严格类型集上覆盖并命中 `3/41`，selective accuracy `1.0`，但 full accuracy 仅 `0.0732`；all-FC 为 `15/41=0.3659`，legacy structural 为 `16/41=0.3902`
- type primary 相对 all-FC/legacy 的 accuracy delta 为 `-29.27pp`/`-31.71pp`，10,000 次 row bootstrap 区间分别为 `[-43.90,-14.63]pp`、`[-46.34,-17.07]pp`。这反映预注册 full-accuracy 端点上的低覆盖失败，不是方法提升
- 预注册 FC-source primary `branch_release_graph` 为 `2/9=0.2222`，coverage `5/9`、selective accuracy `0.4`；prefer-NVD 为 `6/9=0.6667`，latest-published 同为 `2/9`，artifact-bound 为 `1/9`
- branch 相对 prefer-NVD 的 delta 为 `-44.44pp`，bootstrap 区间 `[-88.89,0]pp`；只有 9 条非人类 strict source rows，不能据此推出 NVD 的一般权威性

未验证：

- 两位 reviewer 都是 Codex Agent，不是现实人类 annotator/reviewer；所有 v2 行均为 `label_is_human=false`，现实人类签收仍为 `0`
- v2 对前两批 CVE 零重叠，但仍条件于同一 deterministic FC candidate miner，不能验证 candidate generation 的总体泛化
- 41% strict type coverage 和 9% strict FC-source coverage 都是选择性子集；其余行不能静默丢弃，9 条来源样本不足以支撑稳定方法排序
- type `3/3` 选择性一致只说明一个极低覆盖候选在这三条上未错，不是高性能或实用性证明；source primary 未超过固定来源 baseline
- A 的原始输出把 `unresolved` 写为 JSON null，B 的首版部分 `source_rationale` 低于冻结 validator 的字符下限；均由原 reviewer 只做格式修复，未改标签、来源或证据。字符下限未在 prompt 中显式声明，是本轮协议瑕疵
- v2 已揭封，不能再用于调参后声称独立确认；所有区间均条件于双 Codex strict consensus 和当前小样本

下一步：

- 现实人类复核 v2 全部 100 条，优先检查 15 条 strict FC、9 条 strict source、59 条 type disagreement/abstain；不得把 Codex consensus 直接复制到 human 字段
- 把 v1 task-mixing 和 v2 no-gain 作为论文的协议/失败分析，删除“下一轮 v2 待做”表述，不把 type selective `3/3` 写成方法改进
- source authority、temporal revision、多分支/backport 和 ecosystem ordering 只能在旧开发数据上继续开发；若需要确认性结论，必须另冻 v3 或获得现实人类签收的独立测试集
- 修订下一版 reviewer prompt，使所有字段类型和最小长度显式、机器可读，避免揭封后的纯格式修复

### 29. 已实现并在权威远端运行：v2 失败归因、跨 cohort 候选审计与 v3 no-go 门槛

本次完成：

- 对 v2 揭封结果做 post-hoc 失败归因，分别统计类型方法 false abstention、结构化区间关系、包可比性、branch contradiction 和 strict source 的证据来源依赖
- 实现 `task_separated_type_v2_candidate` 与 `authority_filtered_branch_graph` 两个受限候选，并在 Phase D、v1、v2 三个已揭封 cohort 上统一比较；候选仅用于开发诊断
- 使用不含 CVE/样本 ID、gold label 或 adjudicated source 的结构化特征，运行 leave-one-cohort-out balanced logistic 与 shallow decision tree；每次只用另外两个 CVE-disjoint cohort 训练
- 将推进条件固化为：候选必须在每个留出 cohort 上严格多于最佳命名 comparator 的正确数。类型和来源端点均无通过候选，因此明确不冻结、不消耗 v3 cohort

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/holdout/analyze_affected_versions_v2_failure_modes.py`
- `/home/xiaoyuliang/code/vuln-adj/results/holdout/affected_versions_v2/posthoc_failure_analysis/`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/affected_versions_authority_graph.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/affected_versions_task_separated_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/analyze_affected_versions_task_separated_v2_development.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_task_separated_v2/`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/analyze_affected_versions_leave_one_cohort_out.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/requirements-ml.txt`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/affected_versions_leave_one_cohort_out/`

验证：

- 权威远端为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`），Python `3.13.13`；安装并记录 `scikit-learn==1.7.2`
- v2 failure-analysis、authority candidate、task-separated v2 和 development diagnostic focused tests 分别为 `3/3`、`3/3`、`5/5`、`3/3` 通过；leave-one-cohort-out tests 为 `4/4` 通过
- 远端 `experiments/holdout` 全量测试为 `37/37`，`experiments/rq3_adjudication` 全量测试为 `41/41`；三个诊断生成器均已重跑
- 留一划分的 train/test CVE overlap 均为 `0`；feature key guard 拒绝 identity/gold 字段，并允许正常 branch capability flag
- failure-analysis JSON SHA-256 为 `962587e658150fb274a4133116ab70ee9a2217dd3430bf980f5caa381026cb4d`；development diagnostic 为 `f758d9db64ac7646677af5fcfb5a5f8bc0f9e42b5b9aa7791881b1265fb11d9b`；leave-one-cohort-out artifact 为 `e49c7a62b99885fc86f0fe4f179ebea7e7e4478deb245aa507e98a7913063999`
- 已重建 `paper/cose/full_draft.md`；package validator 的 silver/affected_versions claim-boundary lint 均通过。`submission_ready=false`：RQ2/RQ3 现实人类标签、投稿元数据仍缺，远端还缺 ImageMagick `convert`，旧 LaTeX log 仍有 fatal/emergency-stop

当前效果：

- v2 strict type 的 41 条中，旧 type primary 只覆盖 3 条，其余 38 条 false abstention 为 `13 FC`、`8 INC`、`17 RD`；这不是单一标签类别造成的漏判
- v2 的 9 条 strict FC-source 中，5 条由双方引用同一个 URL，3 条的集体证据仅来自 NVD record；至少一方引用 primary/ecosystem evidence 为 4 条，双方都引用仅 2 条。双 reviewer 独立不能替代证据独立
- `task_separated_type_v2_candidate` 在 Phase D/v1/v2 上分别为 `7/42`、`11/35`、`10/41`；authority-filtered source 分别为 `3/20`、`2/16`、`1/9`，均未形成跨 cohort 稳定改进
- leave-one-cohort-out 类型 balanced logistic 在 pooled OOF 上为 `70/118=0.5932`，高于 pooled legacy `61/118`，但留出 Phase D 时仅 `22/42`，低于该 cohort legacy `27/42`，稳定提升门槛失败
- leave-one-cohort-out 来源 balanced logistic pooled 为 `19/45=0.4222`，低于 branch `27/45=0.6000` 的 full accuracy；留出 Phase D 时为 `7/20`，低于 branch `18/20`，稳定提升门槛失败
- 类型与来源端点的 `advance_to_new_sealed_cohort` 均为 `false`；生产默认保持不变，本轮不启动 v3

未验证：

- 所有三批目标仍是 AI/Codex candidate 或 strict dual-Codex consensus，`label_is_human=false`；本轮没有新增现实人类签收
- failure taxonomy、authority tiers、特征集和模型族都在 v2 揭封后定义，不能解释为预注册或确认性方法
- Phase D、v1、v2 虽 CVE-disjoint，但共享 deterministic FC candidate miner、模型家族和部分证据获取机制；leave-one-cohort-out 不能消除这些依赖
- NVD/vendor/upstream/ecosystem 的权威等级目前只是确定性 provenance class，不是经现实专家验证的 source-truth hierarchy

下一步：

- 不消耗 v3；先由现实人类完成 affected_versions 审核与签收，并把来源所有权、上游 maintainer、生态数据库、披露方和二手聚合器写成可审计证据合同
- 若后续候选先在旧开发数据上满足跨 cohort 稳定门槛，再冻结新 cohort 做确认性评估；否则将 affected_versions 保持为 protocol/failure-analysis 贡献
- 论文明确报告 reviewer independence 与 evidence independence 的差异，以及本轮 no-go 决定，不报告 pooled `70/118` 为独立方法增益

### 30. 已实现并在权威远端运行：RQ2 CWE taxonomy 完整影响面封存双 Codex 审计

本次完成：

- 将 `taxonomy_v1` 的全部 `17/8,066` 条 FC→RD 变更作为完整 impact set，而不是普通随机样本；其中 `16` 个 CVE 与原 RQ2 primary seed 不重叠，唯一重叠为 `CVE-2024-1735`
- 在 reviewer 文件不存在时，生成只含 CWE 集合、漏洞摘要、CWE 4.20 条目和官方 ancestor/descendant path 的 17 行 blind worklist，并封存 current/taxonomy 共 34 条预测、prompt、输入和 builder code hashes
- 在两个独立 `/tmp` 工作区启动全新 Codex reviewer；每个工作区只含 prompt 和 blind worklist，不含仓库、sealed predictions 或另一 reviewer 输出。A 采用 taxonomy→CVE-context，B 采用 artifact-first→context 复核顺序
- 严格 validator 校验 17 行完整覆盖、顺序、reviewer/run identity、枚举合同、rationale 长度和 literal CWE path；merge 还校验 sealed input/code hashes、reviewer mtime、文件路径和内容独立性
- 仅在双方的 set relation、discrepancy label、taxonomy-support verdict 均一致，且双方都不要求 additional review 时进入 strict consensus；另生成 9 行去预测的现实人类 priority worklist

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_cwe_taxonomy_impact_review.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_cwe_taxonomy_impact_holdout.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_cwe_taxonomy_impact_holdout.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/cwe_taxonomy/impact_holdout/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_cwe_taxonomy_impact_agent_a.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_cwe_taxonomy_impact_agent_b.jsonl`

验证：

- 权威远端为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）；builder/merge focused tests 最终为 `7/7` 通过
- 封存前 reviewer A/B 文件均不存在；封存后再次运行 builder 被 `reviewer output exists before sealing` 门禁拒绝，worklist/prediction hashes 未变化
- worklist/predictions/manifest SHA-256 分别为 `bdbad7fc0995f09d59152b96de8cbe0df5d425d534fec9789565b48e69f2c47a`、`b05d0e6ebc663fe9d4123253f93c2502746347d2a3422f5892c6acb504c50215`、`822319b11d6f3a17a71c54ce04ea4a6602ef17646c8f6aee389243d7952e8acb`
- reviewer A/B SHA-256 为 `509fb533130ea4b715b60d90316e90a04232417d367c87e06627d5b73bb6d8f0`、`c3af9a2ade21fd8698876af94d1c20258e00a7a5133b351798640688d0a9024c`；路径、内容、reviewer ID 与 run ID 均不同
- merged candidate/audit/priority SHA-256 分别为 `2404b097abb0e52fc44c9c319ac118dd6ef105dfa19562f4473901f5f232ff3e`、`fa6dacafc0639302af912ab8d80b7b1fc9edd51e92bafd606615c2ddb9ee2c0a`、`2bb5ee98979e3db4f953cc0aa4c80335feec7aafb3b544da5ec016381fbb6da9`
- 已重建 `paper/cose/full_draft.md` 和对应 LaTeX section sources；package validator 的 silver/affected_versions claim-boundary lint 均通过。`submission_ready=false` 仍由现实人类标签、投稿元数据、ImageMagick `convert` 和旧 LaTeX fatal log 等既有项阻塞

当前效果：

- set relation 一致 `17/17`（双方均为 fully ancestor/descendant compatible）；discrepancy label 一致 `15/17`，Cohen's kappa `0.8068`
- taxonomy-support verdict 一致 `12/17`、kappa `0.4371`；这说明官方 path 识别稳定，但“是否足以证明 CVE-specific granularity-only”仍有明显判断差异
- strict consensus 为 `11/17=0.6471`，标签为 `8 RD`、`3 FC`；其余为 2 条 label disagreement 和 4 条双方 uncertain/需复核
- 10 条 primary-seed-disjoint strict rows 上，taxonomy_v1 为 `7/10=0.7`，current 为 `3/10=0.3`，paired delta `+40pp`；10,000 次 row bootstrap 区间为 `[-20,+80]pp`，exact two-sided sign diagnostic `p=0.34375`
- 完整 11 条 strict rows 上 taxonomy/current 为 `8/11` 对 `3/11`；9 条 human priority rows 由 6 条双 Codex 未决和 3 条 strict candidate regression 组成
- 方法状态为 `supported_on_nonhuman_primary_seed_disjoint_impact_rows`，但 production default、human-gold 行数和 final-paper 资格均未改变

未验证：

- 两位 reviewer 都是同一 Codex 模型家族的隔离运行，不是现实人类 annotator/reviewer；全部行继续为 `label_is_human=false`，现实人类签收仍为 `0`
- 17 条是候选规则的完整 impact set，不是 8,066 对记录的代表性样本；它能检验变更方向，不能估计总体 RQ2 accuracy
- taxonomy_v1 方向是在旧 AI candidate error inspection 后提出；16 条 CVE-disjoint 降低行复用，但不能消除模型家族、规则选择和 taxonomy-context 依赖
- bootstrap 区间跨 0、exact diagnostic 不小；当前正向方向不足以解释为独立显著性或生产切换依据

下一步：

- 现实人类优先填写 `cwe_taxonomy_human_priority_worklist.blind.jsonl` 的 9 条，再盲签收剩余 8 条；不得把 dual-Codex consensus 直接复制为 human 字段
- 取得独立 reviewer 与 author sign-off 后，在 17 条完整 impact set 上重算 current/taxonomy paired result；再结合 references 56 条签收决定 combined candidate 是否可进入生产默认候选
- 在现实人类结果可用前，论文只报告 sealed full-impact non-human candidate diagnostic 和 3 条明确 regression，不写 human-gold 或显著改进

### 31. 已实现并在权威远端运行：RQ2 CWE taxonomy 三阶段现实人工复核包与失败关闭门禁

本次完成：

- 基于已经封存的 17 条 CWE taxonomy 完整影响面生成空白人工复核包；包内不预填双 Codex 标签、人工身份或最终结论
- 将现实人工流程拆成 primary annotator、不同身份的 independent reviewer、author resolution/sign-off 三个阶段；`label_is_human` 在工作包层面固定为 `false`，后续 canonical promotion 必须另走受控流程
- 校验器逐行绑定 sealed blind source 的 CVE、字段、NVD/GHSA 值、漏洞上下文、官方 CWE 条目、ancestor/descendant path 和 taxonomy 来源；RD 标签必须引用包内官方路径
- 对人工 ID、rationale 长度、ISO 时间、reviewer 身份独立、最终签字和排除理由执行失败关闭校验；`pending` 行若夹带任何人工内容也会失败
- JSONL 作为唯一权威可编辑输入，CSV 仅供查看；builder 拒绝覆盖已经存在的人工包

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_cwe_taxonomy_human_review_packet.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/validate_cwe_taxonomy_human_review.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/test_validate_cwe_taxonomy_human_review.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/rq2/cwe_taxonomy_impact_human_review/`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/cwe_taxonomy/impact_human_review/`

验证：

- 权威远端 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）focused tests 为 `6/6` 通过，RQ2 目录全量测试为 `13/13` 通过
- 普通校验返回成功：`17` 行、`17 pending`、`0 signed`、`0 excluded`、`0` schema errors、`complete=false`
- `--require-signed` 与 `--require-complete` 均按预期以退出码 `2` 拒绝；builder 再运行按预期拒绝覆盖已有包
- 递归字段核查确认 `9` 条 priority rows、人工 ID `0`、人工标签 `0`、签字 `0`，所有行 `label_is_human=false`
- JSONL/CSV/manifest/readiness JSON SHA-256 分别为 `7604a107c36d072896ea4d37687f9f549d4d92af2ee24c831642b68f06741451`、`0df85506e41bcccfdee02966374aa99beb2c91e7a5168c7e9cf23ad4ec3c92f0`、`192143a9d0097192845bcc87a6ae1ed49ba50cb8c4314b9b11ac24b8f5393661`、`38c5c48b3e226a220242fc732a3e6012716ec39a6b45b75c477b619634539ae1`

当前效果：

- 真实人员现在可以直接在统一 schema 中完成 17 条全影响面复核，并优先处理 9 条未决/回退高风险行
- 当前现实人工签收仍为 `0/17`；本阶段只证明工作包和门禁已就绪，不增加 human-gold 数量，也不改变 taxonomy candidate 或 production default 状态

未验证：

- 尚无真实 annotator、独立 reviewer 或 author 在包内签署；不能把 Codex 的双审结果复制为人工结论
- 尚未实现从已完成复核包到 canonical human-gold 的 promotion；在真实签署出现前不应实现或运行该步骤
- 当前人工包只覆盖 CWE taxonomy 的 17 条完整规则影响面，不替代 RQ2 primary 300 条、consistency 60 条、references 56 条或 RQ3 的现实人工复核

下一步：

- 由真实 annotator 和独立 reviewer 先盲审 9 条 priority rows，再补齐剩余 8 条；作者逐条 resolution 并签字
- 完成后运行 `--require-complete`，再实现单独的 canonical promotion 和 human-gold evaluator；任何一条未通过门禁都不得晋升
- 在现实人工结果可用前保持 `0/17`、`label_is_human=false` 和 production default 不变

### 32. 已实现并在权威远端运行：RQ2 CWE taxonomy 冻结证据增强二次双 Codex 审计

本次完成：

- 复查第一轮 9 条 priority rows，确认 6 条未决主要由短摘要无法证明具体漏洞机制导致，另 3 条为已有严格共识的 taxonomy candidate regression；没有让新 Agent 只重复读取相同摘要
- 从 NVD/GHSA 已列引用中按固定规则为每行选择最多 5 个来源；commit/pull 使用 patch 快照、GitHub blob 使用 raw 快照，并在新 reviewer 文件不存在时封存 9 行 blind worklist、prompt、第一轮 artifact、aligned input、fetcher/builder code hashes
- 第二轮 worklist 不含 current/taxonomy 预测、第一轮 reviewer 标签或 consensus；确定标签必须引用成功抓取快照中的 20–280 字符逐字证据，证据不足必须 `uncertain + low + needs_additional_review`
- 在两个独立 `/tmp` 工作区启动全新 Codex reviewer；C 按 evidence-first，D 按 concrete-mechanism-first 顺序复核。两者只收到相同 prompt 和 blind worklist，输出路径、reviewer ID、run ID 与内容均不同
- merge 门禁校验 sealed input/code hashes、reviewer mtime、9 行完整顺序、枚举合同、rationale 长度、literal CWE path、逐字 quote/URL 绑定和 reviewer 独立性；第二轮未决行不回退使用第一轮标签
- 用预先固定的组合规则：非 priority 的 8 条保留第一轮 strict consensus；priority 行只接受第二轮 strict evidence consensus，否则继续 unresolved

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_cwe_taxonomy_evidence_secondary_review.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_cwe_taxonomy_evidence_secondary_audit.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_cwe_taxonomy_evidence_secondary_audit.py`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/cwe_taxonomy_evidence_secondary/url_cache/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_cwe_taxonomy_evidence_agent_c.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_cwe_taxonomy_evidence_agent_d.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/cwe_taxonomy/evidence_secondary_audit/`

验证：

- 权威远端为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）；secondary focused tests 为 `8/8`，RQ2 目录全量测试为 `21/21`
- 封存前 Agent C/D 文件均不存在；review 后再次运行 builder 被 `secondary reviewer output exists before sealing` 门禁拒绝
- blind worklist 为 9 行、177,297 bytes，SHA-256 `d7c2707c52fc2905a04b7bdec0c9046de17825094be00f6c9d8728f733972b0c`；manifest SHA-256 `797f43479dedfb73e2f0c1098f5425f2974d57a34483f0a67233a1cb38533e66`
- 36 个引用快照状态为 `28 ok`、`4 http_403`、`2 http_404`、`1 http_502`、`1 url_error`；每行至少有 2 个成功快照
- Agent C/D SHA-256 分别为 `de661105847b0f3482e53d700cc3e863a1d240b572f096e91f0a6bacb15f15a8`、`8026be8f024bd64ce2e374164fc0fe8a80611133565a07703c3d8c152c71ce0d`
- secondary/combined/audit SHA-256 分别为 `ccf12e90ad4fb16930c5a99442a2a79317ec32202d0f9704ba70fe924970c4e5`、`0583e08e7761435749a501cc60b99fac45bc433cda9ee592e1d99256d3fde4b0`、`33383648566dd2a6e44c5dad7196fe57567f1363c0126ae36f9188cbc015b74d`
- 已重建 `paper/cose/full_draft.md`；package validator 的 silver/affected_versions claim-boundary lint 均通过。`submission_ready=false` 只继续由既有 ImageMagick `convert` rerender 失败和旧 LaTeX fatal/emergency-stop log 阻塞

当前效果：

- 第二轮 set relation 一致 `9/9`；discrepancy label、taxonomy-support 和 concrete-mechanism verdict 均一致 `7/9`，对应 Cohen's kappa 均为 `0.6087`
- 第二轮 strict consensus 为 `7/9`：`3 RD`（CVE-2023-47320、CVE-2024-29640、CVE-2024-30850）和 `4 FC`（CVE-2024-53305、CVE-2024-8037、CVE-2025-22242、CVE-2025-24959）
- 仍未解决 `CVE-2023-50658`：两位 reviewer 对 PBES2 大迭代计数是否满足 CWE-770 的 reusable-resource 语义分歧；仍未解决 `CVE-2024-11956`：SQL injection 证据是否足以证明 Hibernate-specific CWE-564
- 组合 strict coverage 从第一轮 `11/17` 提升到 `15/17`，标签为 `11 RD`、`4 FC`；4 条 FC 是 taxonomy_v1 的明确 candidate regression，不能因总体方向正向而丢弃
- 14 条 primary-seed-disjoint strict rows 上 taxonomy/current 为 `10/14` 对 `4/14`，paired delta `+42.86pp`，10,000 次 bootstrap 区间 `[0,+85.71]pp`，exact sign diagnostic `p=0.1796`
- 全部 15 条 strict rows 上 taxonomy/current 为 `11/15` 对 `4/15`，bootstrap 区间 `[+6.67,+86.67]pp`，但 exact sign diagnostic 仍为 `p=0.1185`
- 方法状态保持 `nonhuman_evidence_enhanced_development_diagnostic`；production default 未改变，现实人类签收仍为 `0/17`

未验证：

- 第二轮 9 条由第一轮分歧/回退事后选择，不是新的代表性或确认性样本；全 17 条也是规则完整影响面，不是总体随机样本
- 两位新 reviewer 仍是同一 Codex 模型家族，reviewer 分离不等于模型、证据或现实专家独立
- 只有 `28/36` 个来源成功抓取，动态页面文本、第三方 exploit 和引用排序都可能影响裁决；literal quote 证明可追溯，不证明来源内容本身正确
- 小样本 percentile bootstrap 与 exact sign diagnostic 给出不同的边界信号，不能选择性使用正区间声称独立显著性
- 当前输出全部 `label_is_human=false`，不能写成 real human-gold；空白三阶段人工包仍为 `17 pending / 0 signed`

下一步：

- 现实人工优先裁决 2 条二次未决和 4 条 evidence-supported regression，再签收完整 17 条；不得把第二轮 Codex 结果复制成 human 字段
- 取得真实独立 reviewer 与 author sign-off 后，在相同 17 条完整影响面重算 paired result，并与 references 56 条现实签收共同决定 combined candidate
- 论文只把本轮写成 post-hoc evidence-enhanced coverage/boundary diagnostic，不写独立显著改进，不切换生产规则

### 33. 已实现并在权威远端运行：RQ2 references 完整影响面证据双审与 audited development profile

本次完成：

- 先由两个独立只读 Agent 分别审查 references 影响验证的研究边界与实现；两者共同指出完整集只按行数绑定、HTTP/HTTPS 循环证明、网络阳性不复审、worklist 泄露候选变换和截断/缓存证据风险
- 据此将 builder 收紧为：精确绑定 variant diagnostic 的 56 个 CVE、从原 URL 重算所有 normalized sets/status/trigger stage、按 current identity 全覆盖网络证书、保留真实 scheme、记录截断/重试/cache schema，并以锁、原子写和前后哈希检查封存
- 118 个唯一 URL 均在权威远端抓取；网络证书只接受共同 final URL、完整 body hash 或每个 identity 均观察到的精确资源 ID，文本相似度只保留为未校准 diagnostic
- 56 条全部进入 transformation-masked worklist；reviewer 只看到中性 group ID、原始 NVD/GHSA URL 和冻结 probe，不看到规则名、candidate identity、触发阶段、subset side、自动结论或性能
- 首次隔离试运行发现 validator 要求 `insufficient => low + needs_additional_review`，但该合同没有写入已封存 prompt；没有修改 reviewer 输出或事后放宽 validator，而是保留旧 seal/output 为 `superseded_hidden_contract`，补齐 E/F 完整角色 prompt 后重新封存并用全新 E2/F2 ephemeral 会话重跑
- 有效 E2/F2 均审阅完整 56 行；严格 consensus 不使用自动网络阳性回退。合并后再按规则家族定位全部分歧
- 新增 `resource_identity_audited_v1` development profile：保留 HTTPS、Liferay 已知展示 query、精确 GHSA ID 和 Huntr UUID alias，明确关闭 encoded GitHub line suffix stripping；该 profile 在双审结果揭封后选择，显式标记 post-audit

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_reference_identity_evidence_review.md`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_reference_identity_reviewer_e.md`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_reference_identity_reviewer_f.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_reference_normalization_impact_validation.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_reference_normalization_impact_validation.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/analyze_reference_normalization_audited_profile.py`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq2/reference_normalization_identity/url_cache/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_reference_identity_agent_e.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/expert_candidate/batches/rq2_reference_identity_agent_f.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_impact_validation/`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_impact_validation_superseded_hidden_contract/`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_audited_profile/`

验证：

- 权威远端为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`（`hostname=code-defender`）；RQ2 目录 `38/38` 单元测试通过，reference focused script 通过，三个新增脚本 `py_compile` 通过
- source validation 确认 56 个唯一 CVE 与 variant diagnostic 完全一致，所有派生字段重算一致；57 个 proof groups 覆盖 `25 encoded line`、`17 GitHub advisory`、`6 Huntr`、`5 transport`、`4 Liferay query`
- 118 个 probe 为 `88 ok`、`30 http_404`；28 行满足严格网络证书，28 行仅满足结构适用性；全部 56 行仍进入 E2/F2
- 有效 masked worklist SHA-256 为 `be2209d55bbb19b822aaa23d74b0cd97f42499d1a6cc729f6b56008fc0ebad48`；revision-2 sealed manifest 为 `8418c302fa7caa253c8319613350d23fc03839320e94e16b7fe5315789ca707c`
- superseded pilot seal 为 `70c8b86c4c4ae98d1fa5a8fd83a52b3b836b4c864977e1ab4ffbe0ad8774a8a6`；无效 E pilot 与同轮排除的 F pilot SHA-256 分别为 `cf976bd808860b4826ff67ab1d1c8e94fd239555be96218503287e5cb498d24c`、`32d0acf9038fe92c014157e1b9d22e928f42e7a973bf4cff2c24ab3a174da845`，仅保存在 superseded 目录
- E2/F2 输出 SHA-256 分别为 `683cfe7e1135970c57c2e41d446c35bfd794df0bc096c3f6e7ba41e699ea57a9`、`9f0a771e159a700f65abee29062da09525898c039114a0ebd9404b8b09a1d503`
- evidence summary SHA-256 为 `864f178e2ae44fdf1695269608e76542d9746093ab3e4a0bb307bec96a0f2c77`；review 后 `builder --force` 被 `reference identity reviewer output exists before sealing` 门禁拒绝
- audited profile JSON/manifest SHA-256 分别为 `89c63e2f20d9aa2cb513f41036fb6ea2397a12a400fce353fc6b6b1035bbf6bd`、`0ee0ad832b448666cb7e88808fff140a3dd163a9e8d37d1a806cd5a032dbdf40`
- 已重建 `paper/cose/full_draft.md`；package validator 的 RQ2 blank-label、silver 和 affected_versions claim-boundary lint 均通过。`submission_ready=false` 仍由 ImageMagick `convert` 缺失和旧 LaTeX fatal/emergency-stop log 阻塞

当前效果：

- E2 判 56/56 为同一 underlying resource；F2 判 32/56 为同一资源、24/56 为不同 HTTP resource；label/final-status agreement 为 `32/56`，Cohen's kappa 为 `0`，严格 consensus 为 `32/56`
- 24/24 分歧行全部来自 encoded GitHub `%23L...`：E2 按相同 owner/repo/ref/file 的底层文件 identity 解释，F2 按编码文本仍位于 path、请求返回 404 且无 redirect 的可解析 HTTP resource identity 解释
- 其余规则全部严格一致：`17/17 GitHub advisory alias`、`6/6 Huntr UUID alias`、`5/5 HTTP→HTTPS`、`4/4 Liferay presentation query`
- `resource_identity_audited_v1` 关闭 line stripping 后恰好改变 `32/8,066` 行，且 changed CVE set 与 32 条 strict-supported rows 完全一致，全部为 RD→INC
- 在同源非人类 candidate diagnostic 上，references primary 从 `47/59` 提到 `52/59`，review pass 从 `6/11` 提到 `8/11`；分别记录 `5/0` 和 `2/0` corrections/regressions。总体 primary/review 为 `255/283`、`51/55`
- production default 仍为 `current`；全部输出 `label_is_human=false`，现实人类签收仍为 `0/56`

未验证：

- E2/F2 都来自同一 Codex 模型家族，review order 差异不是独立现实专家；grouping 本身仍暴露“这些 URL 正在被测试为一组”
- 24 条 line-suffix 分歧揭示 resource identity 构念未固定；不能选择对候选更有利的 underlying-file 口径覆盖 HTTP 404 证据
- audited profile 是看过完整影响面双审后的 post-audit selection；`52/59`、`8/11` 等指标仍对同源 AI candidate 和规则开发条件化，不能报告为 human-gold、独立 holdout 或显著提升
- revision-2 在无效 pilot 输出出现后才修复合同；虽然旧输出被保留且排除、新 reviewer 只见重新封存输入，但不能声称在任何模型输出前完全预注册
- 重建后的 `full_draft.md` 原始 `wc -w` 为 `13,744`；尚未按期刊口径分离正文、参考文献和元数据计数，投稿前需要重新核算并大概率压缩正文，不能沿用旧的“约 7.8k、低于 10k”表述
- 真实 annotator、独立 reviewer 和 author sign-off 均为 0；生产默认未验证可切换

下一步：

- 现实人工优先定义 reference resource identity 合同，并盲审 24 条 encoded-line 分歧；随后签收 32 条严格非人类共识和完整 56 条影响面
- 在冻结现实人类 holdout 上比较 `current`、原 56-row profile 与 32-row audited profile；只有通过独立 reviewer、author sign-off 和 guarded evaluator 后才决定生产 profile
- 论文仅报告完整影响面分歧结构和 post-audit development profile，不把 candidate agreement 写成确认性性能

### 34. 已实现并在权威远端运行：RQ2 references 三阶段现实人工复核包与失败关闭门禁

本次完成：

- 为 revision-2 封存后的全部 56 条 references 影响行生成 annotator→独立 reviewer→author resolution/sign-off 三阶段空白包；人工字段未预填 E2/F2 判断
- 将 24 条含 encoded GitHub 行号的构念敏感行标为 `definition_sensitive`，其余 32 条标为 `full_impact_confirmation`；两类均保留在完整签收范围内
- 把 `underlying_content_resource`、`frozen_http_resource` 和 `other_explicit_definition` 三种口径写入 manifest，并要求每位人工和最终 author 显式选择；自定义口径必须写明定义
- 新增 fail-closed validator，绑定 revision-2 seal、masked worklist SHA-256、56 条顺序、原始 URL、冻结 probe、group ID、逐组判断、verdict→status 映射、annotator/reviewer 身份差异和作者签署
- pending 行必须保持全部人工字段为空；包本身始终保持 `label_is_human=false` 和 `eligible_for_human_gold_claim=false`，后续 canonical promotion 必须另走受控步骤

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_reference_normalization_human_review_packet.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/validate_reference_normalization_human_review.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/test_validate_reference_normalization_human_review.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/rq2/reference_normalization_impact_human_review/`
- `/home/xiaoyuliang/code/vuln-adj/results/rq2_discrepancy_typing/reference_normalization_impact_human_review/`

验证：

- 权威远端新增 12 个单元测试全部通过；RQ2 目录全量测试为 `50/50`，三个新增 Python 文件 `py_compile` 通过
- 默认 validator 对空白包返回 0：`56` 行、`24` 条 definition-sensitive、`56 pending`、`0 signed`、`0` 个 validation error、`complete=false`
- `--require-signed` 和 `--require-complete` 均按预期返回 2；未签署包不能进入后续金标流程
- 重新运行 builder 因现有人工文件存在而返回 1，拒绝覆盖 JSONL、CSV、manifest 和 README
- builder/validator SHA-256 分别为 `9b89bf237c56fac0f48f00ab4a7609be0e2d9874ea39d7f2cf183fc8ee612f08`、`6c95f0ee12185904a99b9d95e6873af054c3901c77592d7eedadf8a3b96e7eff`
- packet manifest/JSONL SHA-256 分别为 `947c30e593bf34836da77994b76bd63a7b3807530f20f2e818fc64c9237488b9`、`0399643da4a1d396fc604827e4133f6eb1b9b43fd151289d22c3c28012b65cf1`
- package validator 已接入 references/CWE full-impact readiness：两项 readiness shape 校验通过，并将 `references 0/56`、`cwe_taxonomy 0/17` 明确列为投稿 blocker；三项 claim-boundary lint 继续通过
- 已重建 `paper/cose/full_draft.md`，原始 `wc -w` 为 `13,902`；`submission_ready=false`，远端 LaTeX rerender 仍被 ImageMagick `convert` 缺失和既有 fatal/emergency-stop log 阻塞

当前效果：

- References 完整影响面的现实人工工作流已可直接填写和核查；24 条已知构念分歧被优先调度，但未用 Codex 标签暗示人工答案
- 当前仍为 `56 pending / 0 signed`；全项目现实人类签署数量没有增加，不能称已完成人工复核或 human-gold
- 两种预定义 identity 口径的存在只是在协议中显式暴露构念选择，不代表任一口径已被现实专家确认

未验证：

- 尚无真实 annotator、独立 reviewer 或 author 填写/签署任何一行
- 尚未实现 canonical human-gold promotion 与三 profile 的 frozen-human-holdout evaluator；在 56 条完成签收前实现并运行该评估没有有效输入
- 24 条 encoded-line 行最终应采用哪种 resource identity 口径仍需现实专家裁决，不能由当前空白包或 E2/F2 多数关系替代

下一步：

- 先由两位不同现实专家独立填写 24 条 `definition_sensitive` 行，再由 author 记录最终口径、逐组结论和签署
- 随后完成其余 32 条 full-impact confirmation 和全部 56 条签收；运行 `--require-complete` 通过后再构建 canonical promotion
- 在另行冻结的人类 holdout 上比较 `current`、原 56-row profile 和 32-row audited profile，生产默认在此之前保持不变

### 35. 已实现并在权威远端封存：RQ2 fresh-CVE typing stability 队列；双审受接口阻塞

本次完成：

- 启动两个独立只读 Agent 对 RQ2 typing holdout 设计做对照审计。两者一致指出：现有 `8,066` 对快照中，references 的 `56` 条 original / `32` 条 audited 变化行和 CWE 的 `17` 条变化行均已暴露；排除它们后 candidate profile 在当前快照上不可识别。当前队列只能诊断未见 CVE 上的 typing stability，candidate gain 必须等待 profile 冻结后的新时间快照
- 将 `resource_identity_audited_v1` 注册为可调用 reference profile；同时在 seal builder 中直接运行 original reference、audited reference 和 CWE taxonomy 规则，并回归绑定旧语料的 `56/32/17` 个实际变化 CVE，不再用旧 CVE change map 代替规则执行
- 新增 717-CVE exposure denylist，覆盖 RQ2 primary、references/CWE impact、Phase D affected/severity 以及 affected_versions v1/v2；以 70% 比例分配加 30% 等额 audit supplement 形成字段/状态配额，再用确定性二分图增广匹配保证 CVE 跨五字段全局唯一
- blind worklist 改为 aligned raw source projection，只包含原始字段值、摘要、包名、原始引用和单个官方 CWE 条目；删除 baseline-normalized 值、candidate taxonomy path、预测与 sampling stratum，并从 prompt 删除 encoded-line 和 candidate ancestry 的特定判据提示
- 预密封六列预测：`current`、reference original/audited、CWE taxonomy、combined original/audited；runner strict 模式逐行绑定 prompt、worklist 和 seal manifest SHA-256，merge 拒绝 schema 漂移、baseline 泄漏、机械合同改写或 binding hash 不一致
- 在权威远端成功冻结五字段各 `250` 行、总计 `1,250` 行且 `1,250` 个唯一 CVE；A/B worklist 是严格逆序，两个 plan-only 均确认每字段 `250` 行
- 实际启动 A/B 双 Codex review。primary 路由在首批请求返回 `insufficient_quota`；fallback 路由经代理返回 TLS `UNEXPECTED_EOF_WHILE_READING`，去代理直连探针在 180 秒内无响应并被终止。两个 reviewer JSONL 均为 `0` 行，没有产生候选标签

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_typing_holdout.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_rq2_typing_holdout_reviews.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/evaluate_rq2_typing_holdout.py`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq2_typing_holdout_review.md`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/source_rows.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/predictions.sealed.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/blind/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/manifest.sealed.json`

验证：

- 权威远端五个核心 Python 文件均通过 `py_compile`
- `experiments/rq2_discrepancy_typing` 全量单元测试为 `63/63` 通过；runner strict-contract 和 field-profile focused tests 另为 `6/6` 通过
- manifest 记录 `selected_rows=1250`、`selected_unique_cves=1250`、`excluded_union_cves=717`、五字段各 `250`、`candidate_profile_prediction_differences=0`
- original/audited/CWE callable predictor 的 impact 回归分别为 `56/32/17`；已知 development-impact exclusion 后，六列预测逐行相同并由 builder 硬失败门禁保护
- A/B plan-only 均为 `1,250` pending，字段分布相同且顺序互逆；实际 reviewer 文件经 `wc -l` 核查均为 `0` 行
- 已在权威远端重建 `paper/cose/full_draft.md`，原始 `wc -w` 为 `13,990`；package validator 的其余检查执行完成，`submission_ready=false` 仍明确受 ImageMagick `convert` 缺失和既有 LaTeX fatal/emergency-stop log 阻塞

当前效果：

- 当前快照已具备 development-exposure-disjoint、CVE 全局唯一、raw-source blind、prediction-sealed 和 hash-bound dual-review 的 typing stability 队列
- 该队列尚无任何 reviewer 标签、strict consensus 或评估指标；不能写成双审完成、gold、accuracy 或方法增益结果
- 六列预测相同是 exclusion 后的设计事实，只说明当前快照无法识别 candidate impact，不是候选方法有效或无效的结论

未验证：

- primary API 配额尚未恢复；fallback 从权威远端经代理 TLS 失败，直连也未在 180 秒内建立可用响应
- 尚未运行 dual-review merge 和 evaluator；strict coverage、agreement、macro-F1 和 reweighted accuracy 均不存在
- 同模型家族双 Codex 即使完成也仍为 `label_is_human=false`，不能替代现实人类 gold
- 当前 8,066 对不能提供 references/CWE candidate 的独立 profile-disagreement 行；确认性 gain 需要 profile seal 后到达的新 NVD-GHSA cohort

下一步：

- 恢复可用的 `gpt-5.5` OpenAI-compatible 路由后，在不修改 prompt、worklist、profile code 或 seal 的前提下完成 A/B 逆序双审；若发生任何 sealed input/code 修改，必须废弃本轮 reviewer 产物并重新冻结
- 双审完成后运行 strict merge 和 evaluator，只报告 typing stability、严格覆盖、full-cohort lower bound、设计加权指标和 CVE-cluster bootstrap；明确标注 candidate comparison unidentifiable
- 单独预注册未来时间 cohort：从本次 profile seal 之后进入的新 NVD-GHSA 对中收集全部新触发行，并冻结不依赖标签的停止规则；该 cohort 才可比较 current 与 reference/CWE candidates
- 现实人类仍需完成 RQ2 primary `300`、consistency `60`、references `56`、CWE `17` 的独立复核与作者签收；Codex 输出不得写入 human 字段

### 36. 已实现并在权威远端验证：Codex CLI 严格审阅 backend；正式双审仍受 provider 502 阻塞

本次完成：

- 全仓在本地和权威远端分别检索全部已废弃远端地址与旧用户路径，均为零命中；仓库叙事统一使用 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`
- 在权威远端确认 `codex-cli 0.144.4` 可执行，并以 `gpt-5.5`、read-only sandbox、ephemeral session 成功完成最小 `pong` 调用；该路径不读取仓库 `.env` 的 OpenAI-compatible API key
- 为 `run_expert_candidate_annotation.py` 新增 `codex-cli` backend：每批通过 JSON Schema 约束输出，清除继承的 `OPENAI_*` 环境变量，记录 Codex thread ID、token usage、CLI version、二进制 SHA-256、模型和 reasoning effort
- seal builder 绑定 Codex CLI 可执行文件路径、版本、SHA-256、`gpt-5.5`、`high` reasoning、read-only sandbox 和 ephemeral 合同；runner 在调用前检查执行合同，merge 逐行复核并要求 A/B session ID 集合不相交
- 首次 CLI 小批量验证中，A/B 各成功生成 `22` 行；30 行测试暴露 prompt/schema 未声明 validator 的 40 字符 rationale 下限。该部分输出已整体归档为 `superseded_cli_contract_v0`，未进入正式结果
- 将 rationale `minLength=40` 与 evidence URL `uniqueItems=true` 同时写入 schema 和 prompt，再次从零重封正式 `1,250` 行队列；旧 API 失败文件保留在 `failed_api_attempt_20260715`
- 新 seal 下尝试 A/B 30 行和 A 单路 10 行。远端 `xje` provider 持续返回 `502 Bad Gateway`，包括 runner 4 次重试和每次 CLI 内部 5 次 reconnect；正式 reviewer JSONL 仍为 `0/1,250 + 0/1,250`

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/run_expert_candidate_annotation.py`
- `/home/xiaoyuliang/code/vuln-adj/scripts/test_run_expert_candidate_annotation.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/manifest.sealed.json`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/failed_api_attempt_20260715/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/superseded_cli_contract_v0/`

验证：

- 权威远端 runner/builder/merge 通过 `py_compile`
- `experiments/rq2_discrepancy_typing` 全量测试为 `64/64`；runner/profile focused tests 为 `9/9`
- 新 manifest 仍为 `1,250` 行、`1,250` 个唯一 CVE、排除 `717` 个既往暴露 CVE，并绑定 `codex-cli 0.144.4` 和二进制 SHA-256
- `wc -l` 核查正式 reviewer A/B 均为 `0` 行；失败日志为 A `4` 行、B `2` 行。没有 strict consensus、accuracy 或 gold 指标被生成

当前效果：

- API 配额之外已有一条可审计、可恢复、不会把 Codex 输出伪装成人工标签的 CLI 执行路径；schema/validator 隐藏合同已在全量前暴露并修复
- 远端 provider 当前不可用，因此 CLI backend 只完成了执行链验证，尚未完成正式双审
- 本地 Codex CLI 使用另一 provider 且可调用，但按项目远端权威规则，本轮没有把本地生成结果冒充远端实验结果

未验证：

- `xje` provider 的 502 何时恢复无法从仓库内确认
- 正式 A/B 1,250 行输出、strict merge 和 evaluator 仍未运行
- Codex CLI 结果仍只能是 `label_is_human=false` 专家候选；现实 human gold 需要真实人员逐行复核与签署

下一步：

- provider 恢复后按当前 seal 从 A/B 各 10 行开始，以 `--resume` 扩展到全量；不得再修改 runner、prompt、merge、evaluator、worklist 或 manifest
- A/B 完整后先运行 hash/provenance/strict-contract merge，再运行 selective/full-lower-bound/reweighted/bootstrap 评估
- 若需要现实 human gold，由现实 annotator、独立 reviewer 和 author 在现有空白包中签署；Codex 候选可用于排队和证据提示，但不能自动写入 human 字段

### 37. 已实现并在权威远端验证：通用执行合同与 OpenAI 正式 seal；双审因外部路由不可用而阻塞

本次完成：

- 将 runner、builder 和 merge 的封存合同从 Codex CLI 专用扩展为通用 execution backend 合同；OpenAI 路径记录 API route、SDK 版本、response ID 和标准化 token usage，Codex CLI 路径继续记录二进制 SHA-256、thread ID、reasoning effort 和 token usage
- 在 OpenAI-compatible 正式单行请求前发现网关不支持 JSON Schema 的 `uniqueItems`；已删除该关键字，同时保留 prompt 和逐行 validator 对 evidence URL 去重的强制检查。该失败尝试整体归档，未形成标签
- 在权威远端重新封存 `1,250` 行队列；当前 execution contract 明确绑定 `backend=openai`、`api_route=primary`、`openai-python 2.41.0`、`model=gpt-5.5`、`temperature=0` 和 strict JSON schema
- 兼容性修复后，A 的一行正式请求越过 schema 校验并返回 HTTP 402 `insufficient API quota`。A 当前存在 0 个标注行和 2 条请求事件，B 尚未创建；因此正式标注总数仍为 0
- 继续探测已封存过的 Codex CLI 路径：远端 provider 在 30、20、10 和 2 行请求以及 high/medium reasoning 探针上均持续返回 HTTP 502。所有 partial/failed 输出均隔离归档，不进入当前 seal、merge 或 evaluator

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/run_expert_candidate_annotation.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/build_rq2_typing_holdout.py`
- `/home/xiaoyuliang/code/vuln-adj/experiments/rq2_discrepancy_typing/merge_rq2_typing_holdout_reviews.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/manifest.sealed.json`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/failed_openai_schema_v0_20260715/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/holdout/rq2_typing_v1/failed_codex_provider_20260715/`

验证：

- 权威远端 runner、builder 和 merge 均通过 `py_compile`
- `experiments/rq2_discrepancy_typing` 全量单元测试为 `65/65`；runner/profile focused tests 为 `10/10`
- 当前 manifest 为 `selected_rows=1250`、`selected_unique_cves=1250`、`excluded_union_cves=717`、`candidate_profile_prediction_differences=0`，并明确记录 `contains_annotations=false`、`contains_human_labels=false`、`label_is_human=false`
- 正式 `reviewer_a.jsonl` 为 0 个非空行，`reviewer_b.jsonl` 不存在；A 请求日志记录一条执行计划事件和一条 `APIStatusError`，错误消息为 HTTP 402 `insufficient API quota`
- 所有旧 API、旧 CLI 合同、CLI provider 失败和 OpenAI schema 失败尝试均在独立目录留存，没有 strict consensus、accuracy、macro-F1 或 gold 指标被生成

当前效果：

- 双 backend 的执行 provenance、seal binding 和 merge fail-closed 校验已实现并通过远端测试；当前正式 seal 只允许绑定的 OpenAI primary 合同
- 现有路由状态下无法产生第一条正式 reviewer 标签，不能运行 merge/evaluator，也不能汇报 typing stability 指标
- 两个独立设计审计 Agent 的结论保持不变：当前快照六个 profile 预测完全相同，只能在取得标签后诊断 baseline typing stability，不能比较 candidate gain

未验证：

- primary API 配额何时恢复、fallback TLS/直连何时可用、远端 Codex CLI provider 502 何时恢复，均无法从仓库内确认
- 正式 A/B 1,250 行双审、strict merge 和 evaluator 尚未运行
- 任何未来 Codex/OpenAI reviewer 输出仍只能作为 `label_is_human=false` 专家候选；现实 human gold 仍需真实人员复核和签署

下一步：

- primary 配额恢复后，按当前 OpenAI seal 从 A 单行 `--resume`，再完成 A/B 全量；不得修改 prompt、worklist、profile code、runner 合同或 manifest
- 若选择恢复后的 Codex CLI provider，必须废弃当前 reviewer 请求状态并重新封存匹配 CLI execution contract 的新 seal，不能混用 backend provenance
- A/B 完整后再运行 strict merge 和 evaluator；若要比较 candidate gain，仍需另行预注册并冻结 profile seal 之后的新时间 cohort

## 2026-07-14

### 1. 已实现并本地验证：simulated-expert validation fallback

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/build_simulated_expert_validation.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/simulated_expert/README.md`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/simulated_expert/manifest.json`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/simulated_expert/rq2/discrepancy_typing_primary.simulated.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/simulated_expert/rq2/discrepancy_typing_primary.simulated.csv`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/simulated_expert/rq2/discrepancy_typing_consistency_review.simulated.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/simulated_expert/rq2/discrepancy_typing_consistency_review.simulated.csv`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/simulated_expert/rq3/severity_adjudication_audit.simulated.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/simulated_expert/rq3/severity_adjudication_audit.simulated.csv`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/simulated_expert/rq3/affected_versions_adjudication_audit.simulated.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/simulated_expert/rq3/affected_versions_adjudication_audit.simulated.csv`

验证：

- 当时使用了已废弃的错误远端配置并连接超时；该尝试不构成对当前权威远端的可用性验证，正确配置已在 2026-07-15 校正。
- 已运行 `python3 -m py_compile scripts/build_simulated_expert_validation.py`。
- 已运行 `python3 scripts/build_simulated_expert_validation.py`。
- 已核查输出行数：RQ2 primary `300` 行，RQ2 consistency `60` 行，RQ3 severity `80` 行，RQ3 affected_versions `100` 行。
- 已核查 `data/annotations/simulated_expert/manifest.json`，其中 `authoritative_remote_verified=false`、`simulation_only=true`、`gold_label_is_human=false`。
- 已确认没有创建 canonical `data/annotations/rq2/` 或 `data/annotations/rq3/gold_audit/` 目录。

当前效果：

- 本地已有一套可复查的 simulated-expert fallback，用于展示完整 RQ2/RQ3 标注形状与后续 evaluator 接口期望。
- RQ2 primary simulated label 分布：`75 equivalent`，`100 representation_discrepancy`，`88 incomplete`，`15 temporal_discrepancy`，`22 factual_conflict`。
- RQ3 severity simulated label 使用现有 evidence-aware `silver_v2` 作为 proxy：`75 factual_conflict`，`3 representation_discrepancy`，`2 temporal_discrepancy`；裁决来源为 `49 both`，`26 nvd`，`3 ghsa`，`2 abstain`。
- RQ3 affected_versions simulated label 使用旧 Phase D URL-only LLM draft 作为 proxy：`48 factual_conflict`，`18 incomplete`，`12 representation_discrepancy`，`22 uncertain`；裁决来源为 `83 abstain`，`16 both`，`1 nvd`。

未验证：

- 本轮没有在当前权威远端运行验证；不能把本地产物写成远端验证结果。
- 这些文件不是独立 human-gold labels，不能用于报告 gold-backed accuracy、macro-F1、agreement 或 adjudication performance。
- RQ2 标签只是 deterministic baseline proxy；RQ2 consistency 不是独立第二标注者。
- RQ3 severity 是 `silver_v2` proxy；RQ3 affected_versions 仍是旧 URL-only draft proxy，不是 evidence-aware human audit。
- 当前仍缺真实 canonical RQ2 gold 模板、RQ3 `gold_audit` final rows、guarded gold evaluators 和 COSE package validator 的完整当前版本。

下一步：

- 已在 2026-07-15 恢复并校正权威远端访问；canonical RQ2/RQ3 模板和 evaluator 以远端现状为准。
- 若项目接受 simulated-expert 作为替代标注，需先明确在论文和计划中标注为 simulation/proxy，不能称为 human-gold。
- 若目标仍是真实 human-gold validation，应完成 RQ2 primary/reviewer labels、RQ3 severity/affected_versions human audit final rows，并运行 guarded evaluators。

### 2. 已实现并本地验证：simulated-expert validation proxy metrics

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/simulated_expert_validation/README.md`
- `/home/xiaoyuliang/code/vuln-adj/experiments/simulated_expert_validation/evaluate_simulated_expert_validation.py`
- `/home/xiaoyuliang/code/vuln-adj/results/simulated_expert_validation/simulated_validation_metrics.json`
- `/home/xiaoyuliang/code/vuln-adj/results/simulated_expert_validation/simulated_validation_metrics.md`
- `/home/xiaoyuliang/code/vuln-adj/results/simulated_expert_validation/rq3_simulated_predictions.jsonl`

验证：

- 已运行 `python3 -m py_compile experiments/simulated_expert_validation/evaluate_simulated_expert_validation.py`。
- 已运行 `python3 experiments/simulated_expert_validation/evaluate_simulated_expert_validation.py`。
- 已核查输出边界字段：`simulation_only=true`、`gold_label_is_human=false`、`authoritative_remote_verified=false`。
- 已核查 RQ2 primary `300` 行、RQ2 consistency `60` 行、RQ3 severity `80` 行、RQ3 affected_versions `100` 行进入 metrics。
- 已运行 `git diff --check`。

当前效果：

- RQ2 baseline vs simulated label：agreement `1.0000`，macro-F1 `1.0000`。该结果来自 deterministic baseline proxy，不是模型性能。
- RQ2 simulated consistency：exact agreement `1.0000`，Cohen's kappa `1.0000`。该结果来自复制 simulated primary label，不是独立标注者一致性。
- RQ3 severity vs simulated audit：`evidence_score_baseline` agreement `0.6875`、macro-F1 `0.4317`；`prefer_nvd` agreement `0.3250`；`prefer_ghsa` agreement `0.0375`；`latest_published` agreement `0.0500`。
- RQ3 affected_versions vs simulated audit：`prefer_nvd` agreement `0.0100`、macro-F1 `0.0066`；`prefer_ghsa` 与 `latest_published` agreement 均为 `0.0000`。

未验证：

- 本轮仍没有在当前权威远端运行验证；不能写成远端或投稿包验证结果。
- 所有 metrics 都是 simulation/proxy diagnostics，不是 human-gold accuracy、independent agreement 或 final adjudication performance。
- RQ3 affected_versions 本地缺少 evidence-aware token-support prediction file，因此只评估了 fixed-source 和 latest-published baseline。
- 真实 canonical RQ2/RQ3 gold evaluator、COSE package validator 和 submission blocker 仍未恢复到本地当前工作树。

下一步：

- 权威远端已在 2026-07-15 恢复；后续优先推进 canonical RQ2/RQ3 audit workflow，而不是使用本地 simulated metrics。
- 若继续本地 fallback，可补 affected_versions evidence-aware prediction file，再单独标注为 simulated/proxy evaluator。

## 2026-05-12

### 1. 完成：远端运行环境迁移与确定性链路验证

产物：

- `/home/xiaoyuliang/code/vuln-adj`
- `/home/xiaoyuliang/code/vuln-adj/.venv`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/discrepancies/field_discrepancy_stats.json`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/sample_manifest.json`

验证：

- 已用 `rsync` 将本地项目同步到 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj/`
- 同步时未复制本地 macOS `.venv`，已在远端用 Python `3.10.12` 新建 `.venv`
- 已在远端 `.venv` 安装当前脚本实际需要的 `openai` 与 `packaging`
- 已在远端运行 `.venv/bin/python -m compileall -q scripts experiments`
- 已在远端运行 `scripts/build_field_discrepancies.py`
- 已在远端运行 `scripts/build_annotation_samples.py`
- 已在远端运行 `scripts/summarize_llm_annotations.py` 汇总已有 LLM draft
- 已确认 `scripts/run_llm_annotation.py` 可导入，且远端存在 `.env` 与 prompt 文件

当前效果：

- 远端项目目录大小约 `1.3G`
- 对齐输入行数：`100032`
- 字段视图输出匹配对数量：`8066`
- Phase D 样本：`affected_versions` 抽样 `100` 条，`severity` 抽样 `80` 条
- 远端汇总已有 LLM draft 的结果与本地记录一致

未验证：

- 本次没有重新调用 LLM 接口生成新 draft，避免产生新的模型输出或费用
- 没有验证联网抓取 GHSA/NVD 最新数据，只验证了已同步数据上的确定性处理链路
- 当前仓库没有正式依赖清单，远端依赖是按实际报错和脚本导入最小补齐

下一步：

- 若需要长期复现实验，应补充 `requirements.txt` 或等价依赖清单
- 若需要继续跑 LLM 标注，可在远端使用 `.venv/bin/python scripts/run_llm_annotation.py <sample.jsonl>`，并保留 `llm_draft` 非金标属性

## 2026-05-13

### 1. 已实现并运行：RQ3 evidence-aware silver_v2 生成流程

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/build_rq3_evidence_samples.py`
- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/rq3_silver_v2_with_evidence_prompt.md`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence_manifest.json`
- `/home/xiaoyuliang/code/vuln-adj/data/evidence_cache/rq3/url_cache/`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/rq3/silver_v2/llm_silver_v2/severity_fc_adjudication_seed.evidence.llm_draft.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/rq3/silver_v2/llm_silver_v2/severity_fc_adjudication_seed.evidence.requests.jsonl`

验证：

- 已在远端运行 `.venv/bin/python -m py_compile scripts/build_rq3_evidence_samples.py scripts/run_llm_annotation.py`
- 已在远端运行 `scripts/build_rq3_evidence_samples.py`，从 `nvd_context.references` 与 `ghsa_context.references` 抽取候选 URL 并抓取证据视图
- 已在远端使用 `docs/prompts/rq3_silver_v2_with_evidence_prompt.md` 重新运行 LLM 标注
- 已用 `scripts/summarize_llm_annotations.py` 汇总 `silver_v2`
- 已校验 evidence 输入、silver_v2 输出和 request 日志均为 `80` 行，且 `sample_id` 无重复
- 已确认 request 日志中的模型输入包含 `evidence_context`

当前效果：

- severity RQ3 seed 样本数：`80`
- 候选 URL 证据记录数：`470`
- 抓取状态：`406 ok`，`54 url_error`，`4 http_403`，`3 http_404`，`3 timeout`
- 有至少一条成功正文证据的样本：`79/80`
- `silver_v2` 标注完成：`80/80`
- `silver_v2 llm_label`：`75 factual_conflict`，`3 representation_discrepancy`，`2 temporal_discrepancy`
- `silver_v2 is_baseline_false_positive`：`75 no`，`5 yes`
- `silver_v2 adjudicated_source`：`49 both`，`26 nvd`，`3 ghsa`，`2 abstain`
- `silver_v2 confidence`：`69 high`，`11 medium`

未验证：

- `silver_v2` 是 evidence-aware LLM silver label，不是人工 gold
- 证据抓取只保存正文片段与基础元信息，未做人手核验，也未验证动态页面是否完整渲染
- 当前只为 `severity_fc_adjudication_seed` 生成了 `silver_v2`，尚未扩展到其他字段
- 尚未用 `silver_v2` 评估 RQ3 裁决方法

下一步：

- 基于 `silver_v2` 实现 RQ3 裁决方法评估，避免继续使用只有 URL 输入的旧 LLM draft 作为评估标签
- 对 `adjudicated_source` 非 `abstain` 的样本做人工抽查，评估 `silver_v2` 的可用性和风险
- 如需评估 `affected_versions` 或其他字段，复用同一证据抓取与 silver_v2 生成流程

## 2026-05-14

### 1. 已实现并运行：RQ3 severity silver_v2 baseline 评估

产物：

- `/home/xiaoyuliang/code/vuln-adj/experiments/rq3_adjudication/evaluate_severity_silver_v2.py`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/severity_silver_v2_predictions.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/results/rq3_adjudication/severity_silver_v2_eval_metrics.json`

验证：

- 已在远端运行 `.venv/bin/python -m py_compile experiments/rq3_adjudication/evaluate_severity_silver_v2.py`
- 已在远端运行 `.venv/bin/python experiments/rq3_adjudication/evaluate_severity_silver_v2.py`
- 已确认预测明细输出 `320` 行，对应 `80` 个样本 × `4` 个 baseline 方法
- 已将 `results/rq3_adjudication/` 同步回本地

当前效果：

- 评估对象：`severity_fc_adjudication_seed` 的 evidence-aware `silver_v2`
- `silver_v2` 裁决分布：`49 both`，`26 nvd`，`3 ghsa`，`2 abstain`
- `prefer_nvd`：accuracy `0.325`，macro-F1 `0.1226`
- `prefer_ghsa`：accuracy `0.0375`，macro-F1 `0.0181`
- `latest_published`：accuracy `0.05`，macro-F1 `0.0384`
- `evidence_score_baseline`：accuracy `0.6875`，macro-F1 `0.4317`，non-abstain coverage `0.9875`

未验证：

- 这些指标只是在 `silver_v2` 上的 baseline 评估，不是人工 gold 上的最终效果
- `evidence_score_baseline` 是简单文本匹配规则，只匹配抓取到的 `title/text_snippet` 中的 severity label、score 和 CVSS vector，尚未做更细的证据可信度、来源层级或冲突解释
- 当前只评估了 severity 字段，未扩展到 `affected_versions`、`published/date`、`references`

下一步：

- 抽查 `evidence_score_baseline` 错误样本，判断错误来自规则、证据抓取缺失，还是 `silver_v2` 本身不稳定
- 在保留 baseline 标识的前提下，加入更明确的来源层级和证据冲突解释规则
- 若要写论文结果，先补人工抽查或 gold 小样本，避免把 silver-only 指标写成最终结论

## 2026-04-21

### 1. 完成：原始数据清洗与初始对齐

产物：

- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/nvd/nvd_2023_2025.normalized.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/ghsa/ghsa.normalized.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/manifests/bootstrap_summary.json`

验证：

- 规范化与对齐脚本已实际运行
- 汇总清单已落盘，可直接核查记录数

当前效果：

- NVD 规范化记录数：`100032`
- GHSA 规范化记录数：`28785`
- 对齐总行数：`100032`
- 按 `CVE-ID` 匹配到 GHSA 的行数：`8066`

未验证：

- 当前只验证了“数据已可读、可对齐”，还未验证字段级差异标签准确性

下一步：

- 基于对齐结果构建统一字段视图和 discrepancy typing baseline

### 2. 完成：统一字段视图与字段级差异 baseline

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/build_field_discrepancies.py`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/discrepancies/field_discrepancy_stats.json`

验证：

- 脚本已通过 `py_compile`
- 脚本已在当前对齐文件上实际运行并生成输出

当前效果：

- 处理匹配对数量：`8066`
- `severity`：`3106 equivalent`，`3178 representation_discrepancy`，`1749 factual_conflict`
- `published`：`6169 representation_discrepancy`，`1897 temporal_discrepancy`
- `cwe_ids`：`6813 equivalent`，`1146 incomplete`，`84 factual_conflict`
- `references`：`7763 incomplete`，`300 representation_discrepancy`，`3 factual_conflict`
- `affected_versions`：`424 equivalent`，`3311 representation_discrepancy`，`3059 incomplete`，`1272 factual_conflict`

未验证：

- 这是一版 deterministic baseline，不是人工验证后的最终差异类型结果
- `affected_versions` 与 `references` 仍可能存在规则误判

下一步：

- 编写 annotation guideline，并抽样人工核查 50–100 个字段实例

## 2026-04-22

### 1. 完成：收紧 `affected_versions` baseline 误判规则

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/build_field_discrepancies.py`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/discrepancies/field_discrepancy_stats.json`

验证：

- 脚本已通过 `py_compile`
- 脚本已在 `/home/xiaoyuliang/code/vuln-adj/data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl` 上实际重跑
- 输出统计文件与字段视图文件已重新落盘，可直接核查

当前效果：

- `affected_versions`：`424 equivalent`，`3931 representation_discrepancy`，`3059 incomplete`，`652 factual_conflict`
- 相比上一版，`affected_versions.factual_conflict` 从 `1272` 降到 `652`
- 本次新增并实际触发的降级规则包括：
- `221` 条：`end_including` vs `end_excluding/fixed` 且共享 `major.minor` 前缀
- `253` 条：NVD 点版本落在可解析的 GHSA 范围内
- `141` 条：`end_excluding` 字符串前缀截断
- `5` 条：NVD 使用日期字符串作为 `version_end_excluding`

未验证：

- 这仍是规则收紧后的 deterministic baseline，不是人工金标
- 模式 A 只对 `packaging.version.Version` 可解析的版本做比较；不可解析版本仍保持原判
- “不同包导致的版本体系不一致”尚未在上游对齐阶段修复，本轮未在 `compare_affected_versions` 中自动降级
- 尚未对新的 `652` 条 `factual_conflict` 做人工抽样核查，误判率还未验证

下一步：

- 从新的 `affected_versions.factual_conflict` 中抽样 `100` 条进行人工核查
- 记录仍残留的误判模式，决定是否继续收紧 baseline 或转入 annotation guideline 固化

### 2. 完成：相关工作论文材料落盘（开放获取优先）

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/related_work_papers/`
- `/home/xiaoyuliang/code/vuln-adj/docs/related_work_papers/README.md`

验证：

- 已对已保存的 `paper.pdf` 运行 `file`
- 当前目录下已确认有 `13` 个文件被识别为 PDF
- 目录中同时保留了少量无法直接获取全文条目的落地页，便于后续人工补抓

当前效果：

- `docs/related_work_survey.md` 中列出的 `16` 个条目里，`13` 个已落盘为全文 PDF
- `2` 个条目仅保存了落地页：`07_aspect_level_tosem_2023`、`09_vuldifffinder_cose_2025`
- `1` 个条目已定位但当前环境未成功保存：`12_truth_discovery_survey_tbd_2024`

未验证：

- 尚未逐篇核对下载文件是否都是最终出版版；其中部分为 arXiv / accepted version / 作者自存档
- `12_truth_discovery_survey_tbd_2024` 的公开 accepted version 链接在当前环境返回 `HTTP 405`，还未通过浏览器或其他来源复现下载
- ACM / Elsevier 受限条目的全文是否存在其他公开镜像，本轮未做更深的人工检索

下一步：

- 如论文写作需要逐篇精读，先从已落盘的 `13` 篇 PDF 建立笔记或摘录
- 如必须补齐 `07`、`09`、`12` 全文，再用机构访问或作者页面继续补抓

## 2026-05-06

### 1. 已实现并运行：Phase D 人工核查与裁决金标起始抽样

产物：

- `/home/xiaoyuliang/code/vuln-adj/scripts/build_annotation_samples.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/affected_versions_fc_manual_check.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/affected_versions_fc_manual_check.csv`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/severity_fc_adjudication_seed.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/severity_fc_adjudication_seed.csv`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/sample_manifest.json`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/README.md`

验证：

- `python3 -m py_compile scripts/build_annotation_samples.py` 已通过
- `python3 scripts/build_annotation_samples.py` 已实际运行并生成输出
- 已检查 `sample_manifest.json`
- 已用 `wc -l` 核查输出行数

当前效果：

- 从 `affected_versions.factual_conflict` 的 `652` 条候选中抽样 `100` 条
- 从 `severity.factual_conflict` 的 `1749` 条候选中抽样 `80` 条
- 默认随机种子为 `20260506`
- CSV 文件已包含人工标注列：`manual_label`、`is_baseline_false_positive`、`adjudicated_source`、`adjudicated_value`、`evidence_urls`、`evidence_notes`、`annotator_notes`

未验证：

- 当前产物只是待人工标注模板，不是已完成人工金标
- 尚未计算 `affected_versions` baseline 误判率
- 尚未基于外部证据填写 `severity` 裁决值

下一步：

- 人工填写 `affected_versions_fc_manual_check.csv`，统计 baseline false positive 比例
- 若误判率 `> 30%`，继续收紧 `affected_versions` 规则；否则固化 annotation guideline
- 人工核查 `severity_fc_adjudication_seed.csv` 的外部证据，形成 severity 裁决金标初版

### 2. 已实现并完成全量运行：LLM-assisted draft 标注流程

产物：

- `/home/xiaoyuliang/code/vuln-adj/docs/prompts/phase_d_llm_annotation_prompt.md`
- `/home/xiaoyuliang/code/vuln-adj/scripts/run_llm_annotation.py`
- `/home/xiaoyuliang/code/vuln-adj/scripts/summarize_llm_annotations.py`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/llm_drafts/severity_fc_adjudication_seed.llm_draft.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/llm_drafts/severity_fc_adjudication_seed.requests.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/llm_drafts/affected_versions_fc_manual_check.llm_draft.jsonl`
- `/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/llm_drafts/affected_versions_fc_manual_check.requests.jsonl`

验证：

- 已创建项目虚拟环境 `.venv`
- 已在 `.venv` 中安装 `openai==2.34.0`
- `python -m py_compile` 已通过
- `run_llm_annotation.py` 已从项目根目录 `.env` 读取 `OPENAI_API_KEY`、`OPENAI_BASE_URL`、`OPENAI_MODEL`
- 已使用 `.env` 中的 `OPENAI_MODEL=gpt-5.5` 跑完两个样本集
- 已用 `summarize_llm_annotations.py` 汇总全量 draft 输出
- 已校验两个 draft JSONL 均可解析，必需字段存在，且 `sample_id` 无重复

当前效果：

- `severity_fc_adjudication_seed`：完成 `80/80` 条
  - `llm_label`：`76 factual_conflict`，`3 representation_discrepancy`，`1 uncertain`
  - `is_baseline_false_positive`：`76 no`，`3 yes`，`1 uncertain`
  - `adjudicated_source`：`64 abstain`，`13 nvd`，`3 both`
  - `confidence`：`39 high`，`41 medium`
- `affected_versions_fc_manual_check`：完成 `100/100` 条
  - `llm_label`：`48 factual_conflict`，`18 incomplete`，`12 representation_discrepancy`，`22 uncertain`
  - `is_baseline_false_positive`：`46 no`，`30 yes`，`24 uncertain`
  - `adjudicated_source`：`83 abstain`，`16 both`，`1 nvd`
  - `confidence`：`5 high`，`95 medium`
- Prompt 已收紧为：如果输入只有 URL、没有证据正文，LLM 不应裁决为 `nvd` 或 `ghsa`
- 运行中遇到远端 API 过载、TLS 超时和 SSE 增量返回，已在脚本中补充 `--resume`、重试和 SSE 文本解析

未验证：

- 当前 LLM 输出是 `llm_draft`，不是人工金标
- 当前输入没有抓取外部证据正文，因此裁决结果按约束主要应为 `abstain`
- 少量 `adjudicated_source=nvd/both` 的样本需要人工检查是否违反“无证据正文不选边”的约束

下一步：

- 对 `affected_versions` 中 LLM 判为 baseline false positive 的样本优先人工复核
- 若要形成裁决金标，需要先抓取/保存证据正文，再允许 LLM 或人工基于证据正文裁决

## 2026-07-19：完成 eligible-universe 34 条 prediction difference 的两类字段专用非人工审计

- 本次完成了什么：
  - 对完整 29 条 `cwe_ids` profile difference 冻结字段专用合同、29 行正反序 blind worklist、85 个 ranked URL evidence records 和 Codex CLI 执行合同；E/F 各 6 个 ephemeral session 完成双审。
  - fail-closed merge 与独立 verifier 均通过；严格共识 `26/29`，candidate/current/neither/unresolved=`25/1/0/3`，条件 exact two-sided p=`8.046627044677734e-07`。该值仅是揭封后完整差异集上的同模型条件诊断。
  - 对完整 5 条 references union 冻结 profile-independent URL partition 合同、26 个唯一 `rq2_reference_probe_v2` records（`24 ok + 2 http_404`）、source-side-hidden 的正反序 worklist，以及 underlying/HTTP 两个预定资源定义。
  - references v1 在写 consensus 前因 merge 调用不存在的 writer 失败；将 seal、reviewer 输出和当时代码归档为 `reference_difference_partition_v1_failed_merge_code_attempt.tar.gz`，SHA-256=`d79c15e9ce6553bc3ffacae8d6e7dede9b6276d3e80cfd2b2e65c0a721e9dbec`。revision 2 把该归档纳入新 seal，重新执行 E/F 后 merge 与独立 verifier 通过。
  - references v2 的 underlying 完整分区 strict=`1/5`、unresolved=`4/5`；HTTP 分区 strict=`3/5`、unresolved=`2/5`，三条 strict 均为 `incomplete`。current-vs-original 与 current-vs-audited 的 HTTP 条件 exact p 均为 `0.25`。低 underlying coverage 来自整行其他页面的 partition 分歧，未按目标 alias 局部一致进行事后放宽。
- 产物路径：
  - `data/annotations/holdout/rq2_post_profile_snapshot_v1/cwe_eligible_difference_evidence_v1/`
  - `results/holdout/rq2_post_profile_snapshot_v1/review/cwe_eligible_difference_evidence_v1/`
  - `data/annotations/holdout/rq2_post_profile_snapshot_v1/reference_difference_partition_v2/`
  - `results/holdout/rq2_post_profile_snapshot_v1/review/reference_difference_partition_v2/`
  - `data/annotations/holdout/rq2_post_profile_snapshot_v1/reference_difference_partition_v1_failed_merge_code_attempt.tar.gz`
- 如何验证：
  - 权威环境再次核对 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`。
  - CWE 聚焦测试 `4/4`、all-50 复用回归 `13/13`；references 聚焦测试 `4/4`、normalization 回归 `29/29`。
  - `verify_rq2_post_profile_eligible_universe_cwe_difference_review.py` 与 `verify_rq2_post_profile_reference_difference_partition_review.py` 均通过；两类 E/F run/session 集合互斥，worklist 哈希与正反序关系通过。
- 当前观察：
  - CWE candidate 在完整揭封差异集中得到很强的同模型证据方向，但仍有一个 current-direction case 和三个 unresolved；不能据此宣称 accuracy、确认性 gain 或 production promotion。
  - references 的三条 advisory-alias 行在 HTTP 定义下形成 strict `incomplete`，两个 encoded-line 行因一个 URL 为 404 而 unresolved；完整 underlying partition 还暴露出 NVD/advisory/第三方页面的 ontology 分歧。
- 还没验证的点：
  - 两项审计都没有真实人类标签、独立真人 reviewer 或 author signoff；`label_is_human=false`。
  - 没有 strict event-time cohort，也没有概率抽样 control layer，因此不能报告 absolute accuracy、prevalence 或 future-snapshot generalization。
  - sealed 250-row evaluation 未改变；references/CWE 现实人工 full-impact packet 和 250-row full-cohort packet仍为 `0 signed`。
- 下一步：
  - 完成 package validator、论文、LaTeX 和视觉产物的同步验证。
  - 实证优先级仍是现实人员签署 250-row full packet、CWE 17-row packet 与 references 56-row packet；未来严格 cohort 必须在 label 前冻结 prediction census、paired difference layer 和 probability-sampled absolute layer。

### 2. 完成：重建论文包并修复 PDF 联系表完整性门禁

- 本次完成了什么：
  - 重建 Markdown 与 LaTeX 论文包，并将 eligible-universe 两类字段专用审计纳入 package manifest。
  - 视觉检查发现当前 PDF 为 87 页，而旧联系表只覆盖 85 页；定位为 package validator 在 `latexmk` 之前检查联系表 freshness，导致构建后的新 PDF 可使已通过的联系表过期。
  - 新增 `build_pdf_contact_sheet.py`，在 LaTeX 构建后调用 `pdfinfo` 和 `pdftoppm` 渲染全部页，并保存 source PDF SHA-256、独立页数、完整页号序列、联系表 SHA-256 与尺寸 manifest。
  - package validator 现按“生成输出、构建 LaTeX、重建联系表、校验视觉产物”执行，并对 PDF/source identity、`1..N` 完整页序列和联系表输出 identity fail closed。
- 产物路径：
  - `experiments/paper_artifacts/build_pdf_contact_sheet.py`
  - `experiments/paper_artifacts/validate_cose_package.py`
  - `experiments/paper_artifacts/test_validate_cose_package.py`
  - `results/paper_cose/visual_checks/pdf_contact_sheet/main_contact_sheet.png`
  - `results/paper_cose/visual_checks/pdf_contact_sheet/main_contact_sheet.json`
  - `results/paper_cose/cose_package_manifest.json`
- 如何验证：
  - 权威环境核对为 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`。
  - package validator 单测 `11/11` 通过；RQ2 全目录回归 `356/356` 通过。
  - 完整 `validate_cose_package.py` 为 `124/124` checks 通过、`status=pass`、`submission_ready=false`。
  - 当前 PDF 为 87 页、572,076 bytes，SHA-256=`65b67bd46aefd339c9cb9e9e2240478142c4f35936ff892105410706d9ff7588`；联系表 manifest 记录并验证 `rendered_pages=1..87`，末三页为 `85,86,87`。
  - 目视检查 948x4706 联系表，确认第 1 到第 87 页连续可见，第 86、87 页位于最后一行，未观察到空白渲染、裁切或页面重叠。
- 当前观察：
  - `paper/cose/full_draft.md` 原始 `wc -w=26,778`，SHA-256=`0f7b9f1cdd4a339e418d0e7026af830de5266e2a5bc794c3555f3098795cf61e`。
  - package 执行验证通过，但五类现实人工/投稿元数据 blocker 不变，不能据此写成投稿就绪。
- 还没验证的点：
  - 现实人员仍未签署 RQ2 1,250/250/56/17 行人工包；RQ3 的 80/100 行人工 audit 仍为空。
  - 作者、单位、通信信息、利益冲突、资金、CRediT 与生成式 AI 声明仍含占位符。
  - 联系表适合全局扫描，不能替代作者对正文、长表、引用和附录的逐页终审。
- 下一步：
  - 优先完成现实人工标注/复核/author signoff 和投稿元数据；结果落盘后重新构建并执行同一 package/视觉门禁。

### 3. 完成：第二次官方采集与 strict event-time 可用性差分审计

- 本次完成了什么：
  - 保留 v1 不变，在独立 `rq2_post_profile_snapshot_v2` 路径重新抓取 NVD 2026 feed 和 GitHub Advisory Database 主分支，并重跑标准化、NVD-GHSA 对齐和字段视图构建。
  - 新增 label-free acquisition-delta 构建器，分别比较 normalized source records、全部 aligned rows、单一 GHSA matched rows 和 derived field views。
  - 新增独立 verifier，从绑定的 profile seal、两个 acquisition manifests、四份 normalized source files、aligned rows 和 field views 重算所有 delta 与 strict-readiness decision。
  - 因 strict event-time unique CVEs 仍为 `0<25`，未构建、未抽样、未标注新的 cohort。
- 产物路径：
  - `data/raw/time_cohort/rq2_post_profile_snapshot_v2/`
  - `data/processed/time_cohort/rq2_post_profile_snapshot_v2/`
  - `results/holdout/rq2_post_profile_snapshot_v2/acquisition/`
  - `results/holdout/rq2_post_profile_snapshot_v2/acquisition_delta_v1_to_v2/`
  - `experiments/rq2_discrepancy_typing/analyze_rq2_post_profile_acquisition_delta.py`
  - `experiments/rq2_discrepancy_typing/verify_rq2_post_profile_acquisition_delta.py`
- 如何验证：
  - 权威环境再次核对 `hostname=code-defender`、`pwd=/home/xiaoyuliang/code/vuln-adj`。
  - `verify_rq2_post_profile_snapshot.py` 对 v2 acquisition 通过，重算结果为 `strict=0`、`external=5,948`、tier=`snapshot_external`。
  - acquisition-delta 聚焦测试 `3/3` 通过，独立 verifier 返回 `strict=0 decision=wait_for_bilateral_post_freeze_records`。
  - RQ2 全目录回归更新为 `359/359` 通过。
  - 论文重建后完整 package validator 为 `127/127` checks 通过、`status=pass`、`submission_ready=false`；新增 acquisition-delta hashes、boundary 和 independent-verifier 三项均通过。
  - 当前正文原始 `wc -w=27,050`，SHA-256=`dbc018bc93125c0da50b9b794a1286726bc8429b3235dd78d9f947e9558ab720`；PDF 为 88 页、574,346 bytes，SHA-256=`15d758b0320bfd0bae5138ba07e9b4f9d469653cf4f1fab6604771e65afa4b95`。
  - 88 页联系表已验证 `rendered_pages=1..88` 并目视检查，未观察到空白渲染、裁切或页面重叠。
- 当前观察：
  - NVD normalized records 从 `34,056` 增至 `34,130`：新增 `74`、删除 `0`、内容变化 `26`；其中冻结后发布和“新增且冻结后发布”均为 `39`。
  - reviewed GHSA records 仍为 `33,347`：新增、删除、内容变化、冻结后发布均为 `0`，尽管仓库 commit 已从 `95e6ff620d5494b93ba2234edfcf6a45187dc0a8` 更新为 `424512debdca84cc53ffa1fb3810a74f7b1905a5`。
  - 单一 GHSA matches 保持 `5,948`，新增/删除/变化均为 `0`；field-view SHA-256 前后相同。
  - 当前 bottleneck 明确为 `no_ghsa_records_published_after_profile_freeze`，不是下载失败，也不是 NVD 没有更新。
- 还没验证的点：
  - 该结果只证明本次采集时尚无双边冻结后事件时间匹配，不估计 GHSA 更新等待时间，也不证明未来采集仍为 0。
  - acquisition delta 不含 correctness label，不是 temporal validation、human gold、accuracy 或 future-snapshot generalization。
- 下一步：
  - 保持 profile seal 不变，在 reviewed GHSA 出现冻结后发布记录后重复同一 label-free acquisition/delta/verifier；只有 strict unique CVEs 达到预定最低 `25` 时才冻结每字段 5 行的新 cohort。
  - 不在已揭封 v1 snapshot 或现有 250 行上增加第三个同模型 vote；现实人工签收 blocker 保持不变。

## 2026-08-23：启动 JSS 保守重构并冻结 T1 结果无关协议

- 本次完成了什么：
  - 在权威远端再次核对 host、路径、branch、HEAD 和 worktree；从
    `main@760523caa8677c7e1e98c3b5be376d08c250f8d6` 创建独立工作分支
    `codex/jss-framing-b-20260823`，保留原有脏工作区，不批量纳入 4,398 个
    未跟踪文件。
  - 将当前论文阶段固定为 `S1_EVIDENCE_LOCKED`，把 JSS 论证标为
    `S2 candidate`；COSE 88 页稿和 2026-07-19 package 降为历史证据线，不再
    视为当前投稿稿。
  - 落盘 JSS paper brief、evidence ledger、claim ledger、argument plan、
    submission blocker ledger 和 machine-readable state；明确 JSS 主路线、IST
    备选、SANER RR 仅适用于未来未揭示结果的确认性阶段。
  - 冻结 T1 双真人 taxonomy validation 协议。V1 的完整绑定测试在任何真人标签
    前发现历史 300-row seed 有 2 行 stale `package_names` context，因此 V1
    fail closed；V2 改为直接从当前 field view 重新随机抽取 300 行，再拆为
    50-row calibration 和 250-row evaluation。两位不同真人全量独立评审、
    baseline 与 AI/Codex 输出盲化、`uncertain` 保留、author adjudication 在
    baseline unseal 前完成。
  - 实现并实际运行 V2 prepare-only packet builder、独立 validator 和 4 项测试；
    生成 A/B calibration/evaluation packets、完整 sampling frame、sealed mapping、
    role record 和 hash manifest。distribution gate 按设计保持关闭。
  - 明确 T1/T2 为正向 JSS framing 的必需实验；affected_versions 现有结果是
    no-go/failure evidence，不是方法增益；temporal claim 默认删除。

- 产物路径：
  - `paper/jss/README.md`
  - `paper/jss/PAPER_BRIEF.md`
  - `paper/jss/EVIDENCE_LEDGER.md`
  - `paper/jss/CLAIM_LEDGER.md`
  - `paper/jss/ARGUMENT_PLAN.md`
  - `paper/jss/SUBMISSION_BLOCKERS.md`
  - `paper/jss/paper_state.json`
  - `paper/jss/manuscript.md`
  - `experiments/rq2_discrepancy_typing/T1_HUMAN_VALIDATION_PROTOCOL.md`
  - `experiments/rq2_discrepancy_typing/build_t1_human_validation_packet.py`
  - `experiments/rq2_discrepancy_typing/validate_t1_human_validation_packet.py`
  - `experiments/rq2_discrepancy_typing/test_t1_human_validation_packet.py`
  - `data/annotations/rq2/t1_human_validation_v2/`

- 如何验证：
  - 权威运行环境为 `hostname=code-defender`、
    `pwd=/home/xiaoyuliang/code/vuln-adj`。
  - 新分支为 `codex/jss-framing-b-20260823`，branch point 为
    `760523caa8677c7e1e98c3b5be376d08c250f8d6`。
  - 本轮 9 个作用域明确的 JSS/T1 文件形成提交
    `f61fec45aa5a19fb75567003185f8612b03df01f`；V2 builder、validator、协议修订
    和空白 packet 形成提交
    `659831571df7d4b0a3ae6549afd0fc8dae5a6927`。两者均未 push。总计划、
    进度日志和更新 HEAD 后的 `paper_state.json` 仍在工作区，未把既有大批改动
    混入上述提交。
  - 当前 field view 为 8,066 行，SHA-256
    `c4bb405399bd0050c206b63ece95771c4f566a9a3968f123a16cf02a3b5cc3a2`。
  - 历史 300-row seed 的 core values/statuses 与当前 field view 匹配 300/300，
    但 full context 仅 298/300：`rq2_discrepancy_typing:145` 与 `:279` 的
    NVD `package_names` 仍含已被 input repair 移除的
    `enterprise_linux`。因此历史 seed/manifest 不再作为 T1 输入。
  - V2 从当前 field view 直接重抽 300 行；新 sampling frame 与当前输入 full
    context 匹配 300/300。calibration/evaluation 为 50/250，A/B 各自文件行数
    50+250，sealed frame/mapping 各 300 行。
  - T1 packet 测试 `4/4` 通过；独立 validator 返回 PASS；加
    `--require-distribution-ready` 返回 exit 2，证明未满足 author/human gate
    时不会误报可分发。
  - V2 packet manifest SHA-256 为
    `816d1d274237ae4d276b7db0925d46255f07b3ea9f39c410ae42eb68a675b1ac`，
    协议/builder/validator SHA-256 分别为
    `7935454181e8de32d20f3a08c755bbda02787425594afe966bccfdd2876d5282`、
    `1b6c790f08e8664d30c235ee39eb07b311d9230b7074124446900810d1c8696b`、
    `ab5dda9b2418e703fcdc4627fd51ccbe1b70c7a5557c573e63c279719efaaaca`。
  - 首次 V2 生成的 CSV 使用 Python 默认 CRLF，`git diff --check` 将其判为
    trailing whitespace。该尝试整体移至
    `/tmp/vuln-adj-t1-human-validation-v2-crlf-attempt-20260823`，未进入当前
    manifest；builder 固定 `lineterminator="\n"` 后用同一 seeds 全量重建并
    重新验证。
  - 对 LF 版本抽查时发现 references `field_context` 仍含
    `nvd_urls/ghsa_urls` 显式键名；该版本整体移至
    `/tmp/vuln-adj-t1-human-validation-v2-explicit-source-key-attempt-20260823`。
    最终 builder 将 prefixed context 投影为中性的 `urls/hosts`，validator
    对 reviewer-side 任意 NVD/GHSA 键名 fail closed；最终显式 source-key 扫描
    通过。URL 值仍可能暴露来源，继续作为既定 threats 保留。
  - `paper_state.json` 由 paper-writing-orchestrator state validator 检查。
  - Markdown link/path、JSON 语法、`git diff --check` 和 scoped Git 状态在本轮
    最终复核中执行。

- 当前观察：
  - 历史 300-row seed 不能作为当前 T1 frame：除 template 暴露
    `baseline_status`、manifest 未绑定 source hash、consistency review 只覆盖
    20% 外，完整验证还发现 2 行上下文漂移。V2 通过重抽当前 frame 修复 provenance，
    不是按标签结果换样；V1/V2 均未接触真人标签。
  - V2 与历史 seed 在 300 个 field instances 上重叠 23 行；这是两个固定随机
    分层样本的自然重叠。真人 reviewer 尚未见过历史包，但该重叠仍应在 threats
    中披露。
  - JSS 可投性仍是条件式，不是当前 GO。最小科学路径是 T1 construct
    reliability 加 T2 downstream utility；继续增加同模型 votes、事后 graph cases
    或机械 package checks 不会解除该门禁。

- 还没验证的点：
  - T1 calibration guideline 仍为 draft，role/independence record 尚未填写；
    两位真人 reviewer 尚未招募，现实人工标签仍为 0，V2
    `distribution_allowed=false`。
  - T2 action map、workload unit、binary comparator 和 result code 尚未冻结。
  - JSS 正文尚未开始；`paper/jss/manuscript.md` 只是明确标记的空 shell。
  - 完整当前 JSS author requirements、作者元数据、最终 PDF 与 artifact package
    尚未核对。

- 下一步：
  - 作者逐条确认并签署 calibration guideline、reviewer 资格、角色独立性、
    ethics/compensation 记录；随后另做 distribution-readiness manifest revision。
  - 只有独立 readiness validator 允许分发后，才向两位真人发送各自 calibration
    packet；未满足前不得写“人工标注已开始”。

## 2026-08-24：清理历史脏文件并建立可恢复的 Git/payload 边界

- 本次完成了什么：
  - 在权威环境 `code-defender:/home/xiaoyuliang/code/vuln-adj` 从
    `659831571df7d4b0a3ae6549afd0fc8dae5a6927` 新建
    `codex/repo-hygiene-20260824`，未直接修改 `main`，未 push。
  - 整理前确认工作目录约 `2.3G`、21 个 tracked 改动和 4,399 个真实未跟踪
    文件。先保存全部 untracked tar、tracked binary patch、status 路径清单和
    SHA-256，再开始删除或提交。
  - 把源码、测试、protocol、prompt、论文源文件、小型 README/manifest 分成
    多个逻辑提交；raw/processed、results、外部论文 PDF、evidence cache 和
    历史生成 payload 保留在权威机器并精确忽略。
  - 从 Git 移除本机 `.claude/settings.local.json`，继续保留本地文件；`.env`
    仍被忽略且未进入 index。
  - 删除 9 个 `__pycache__` 目录、2 个零字节历史 `.build.lock`、
    `docs/.DS_Store` 和误生成的 `ed -n 1,260p AGENTS.md`。13 个删除候选在删除前
    另存 tar，SHA-256 为
    `2319705661a8465c067acb4baf6a058dbb91442e4bbb219ed375219f914e79da`。
  - `git count-objects` 另发现两个共 268 bytes 的 `tmp_obj_*` 临时对象；`git fsck`
    未把它们识别为可达对象。没有运行 `gc`/`prune`，而是逐个移入恢复目录的
    `git-temporary-objects/`，对象库复查为 `garbage: 0`。
  - 解决 `paper/cose/SUBMISSION_READINESS.md` 与
    `paper/cose/submission_readiness.md` 的大小写冲突：引用和 validator 均使用
    较新的小写版本，因此删除旧大写副本。
  - 修复 15 个 RQ2/protocol 文件的多余 EOF 空行，以及两张 COSE CSV 的 CRLF；
    均为机械格式修复，没有改实验逻辑或表格值。

- 产物路径：
  - `docs/repository_hygiene/README.md`
  - `docs/repository_hygiene/retained_local_payloads.sha256.tsv`
  - `scripts/build_repository_payload_manifest.py`
  - `scripts/test_build_repository_payload_manifest.py`
  - 仓库外恢复点：
    `/home/xiaoyuliang/archives/vuln-adj-pre-hygiene-20260824T104541+0800`

- 如何验证：
  - 整理前 `untracked-files.tar` 包含精确 4,399 个成员，SHA-256 为
    `e80a919f20d264013a72343f0fa9c9d93729f3c91f91c3838a6584a1369e8acd`；
    tracked patch SHA-256 为
    `feae02349a66a0bf805cce218a2cec2a774590524ef2f4a349e6232cf362978a`。
  - payload builder 与 verifier 对 4,361 个 ignored 本地文件、
    `2,296,239,806` bytes 完成逐文件大小和 SHA-256 核对。
  - scripts discovery 测试 `18/18`（其中 payload 工具专项为 `2/2`）、RQ2
    测试 `363/363`、AI-adjudicated 测试 `4/4`、holdout 测试 `37/37`、RQ3
    测试 `41/41`、COSE artifact 测试 `14/14` 通过，共 `477` 个现有测试。
    `expert_candidate_validation` 当前没有 `test_*.py`，只完成语法检查，不能写成
    测试通过。
  - T1 prepare-only 独立 validator 继续返回 PASS，且
    `distribution_allowed=false`、`human_labels=0`。
  - `git fsck --no-dangling` 通过；移走两个临时对象后 `git count-objects`
    返回 `garbage: 0`，tracked path 大小写冲突扫描和精确凭据扫描均通过。
  - 分步提交：`78c8f6d`（payload 边界）、`8ec0280`（核心数据/标注工具）、
    `dcf1a50`（RQ2 lineage/protocol）、`8f1437e`（RQ3/holdout 工具）、
    `b12dbdb`（历史 COSE 源码包）。
  - 全仓凭据扫描的初版宽泛 `sk-` 正则误命中 Endor Labs URL 中的普通
    `risk-known-...` 片段；不输出匹配值并核对上下文后，改用只接受 legacy
    alphanumeric 或 `sk-proj-` 形式的精确规则复扫。该命中不是凭据。

- 当前观察：
  - 原始 Git 脏状态主要来自长期未提交的可审查源码/协议，以及本地科研 payload
    混在同一工作树；不是单纯缓存。采取“源码入 Git、payload 保留并哈希绑定”后，
    没有为了状态变干净而删除历史科研证据。
  - payload manifest 只证明当前本机字节完整；不证明 source authority、标签为真人、
    实验有效或论文可投稿。仓库清洁也不解除 T1/T2 blocker。

- 还没验证的点：
  - 本轮没有重跑所有耗时的端到端采集、LLM 调用和 COSE 88 页重建；只验证现有
    源码测试、控制文件、当前 payload 字节和 T1 prepare-only gate。
  - 历史 payload 中的 same-model、failed attempt、post-hoc 资产仍保留原证据上限；
    其存在或 manifest 通过不等于结果可用于主张。

- 下一步：
  - 作者决定是否把整理分支推送并经 review 合并；未明确授权前不 push。
  - 科学主线仍回到 T1 真人 reviewer/guide gate，完成前不启动 T2 正式比较。

## 2026-08-24：完成相关工作证据库与 JSS framing 资格审计

- 本次完成了什么：
  - 在权威远端从 `codex/repo-hygiene-20260824@eb292e3` 新建
    `codex/literature-framing-20260824`，不修改 `main`，不自动 push。
  - 复核仓库已有 16 篇全文，按漏洞差异检测、字段/数据库质量、自动 curation、
    公开数据集/修复证据、truth discovery 和拒判/learning-to-defer 路线补检 8 篇。
  - 新取得 7 篇公开全文 PDF；`Can the Common Vulnerability Scoring System be
    Trusted?` 当前只取得官方/DiVA 元数据和作者摘要，明确保持
    `abstract_only_closed_access`，未补造全文实验细节。
  - 为 24 篇全部建立独立中文解析，逐篇覆盖问题链、机制链、实验逻辑、结论强度、
    局限、可复述版本、对本项目的可迁移点和审稿问题。
  - 建立跨论文能力矩阵、same-task baseline/resource 清单和独立 JSS framing/
    实验缺口审计；将旧 `related_work_survey.md` 降为权威入口，停止沿用其中
    “与现有工作根本不同”等过强表述。
  - 新增 manifest builder，对报告结构、每目录 PDF 数量、页数、文本词数、字节数和
    SHA-256 做机器复核；同步更新仓库 retained-payload manifest。

- 产物路径：
  - `docs/related_work_papers/README.md`
  - `docs/related_work_papers/*/analysis_zh.md`（24 篇）
  - `docs/related_work_papers/literature_manifest.json`
  - `docs/related_work_synthesis_20260824.md`
  - `paper/jss/FRAMING_AND_EXPERIMENT_GAP_REVIEW_20260824.md`
  - `scripts/build_related_work_manifest.py`
  - `docs/repository_hygiene/retained_local_payloads.sha256.tsv`

- 如何验证：
  - 权威环境再次核对为 `hostname=code-defender`、
    `pwd=/home/xiaoyuliang/code/vuln-adj`。
  - `python3 scripts/build_related_work_manifest.py` 返回
    `PASS papers=24 full_pdf=23 abstract_only=1`；23 个 PDF 均可由 `pdfinfo` 和
    `pdftotext` 读取，manifest 绑定每个文件的 pages/bytes/text words/SHA-256。
  - 新增 PDF 均保持 ignored local payload，仓库 retained-payload manifest 从
    `4,361` 个文件、`2,296,239,806` bytes 更新为 `4,368` 个文件、
    `2,302,121,200` bytes；独立 `--verify` 返回 PASS。
  - 24 个解析均通过十个必需章节检查；JSON 由 builder 重建；`git diff --check`
    通过。AppleDouble `._*` 传输垃圾在进入 Git 前删除。

- 当前观察：
  - TOSEM 2023 已明确区分 expression variation 与 semantic difference，并在后者中
    分析 aspect absence/mismatch；VuldiffFinder 也已占据漏洞文本不一致检测。
    因此不能把“首次做差异类型/检测”作为主贡献。
  - CVSS Bayesian 摘要声称在其模型和五个数据库中 NVD 相对最好，这构成
    “跨源差异等于 NVD 错误”的重要反例；因全文未取得，目前只作 provisional
    约束，不引用定量细节。
  - 当前最可守的差异是 action-oriented、field-specific type-first routing，加显式
    abstention 与 identifiability/failure limits；但它仍只是 conditional framing。
  - 文献共同要求把系统效用与分类准确率分开。只有 T1 真人构念和 T2 独立 action
    utility 支持后，才能把 type-first routing 写成正向贡献。

- 还没验证的点：
  - 本轮是 targeted literature review，不是完整 systematic review；投稿前仍需按
    索引库/引用图刷新检索，并核对 2025–2026 preprint 的最终出版状态。
  - 第 18 篇全文、其 Bayesian 先验/来源依赖/敏感性和具体实验表尚未核实。
  - 本轮没有产生 human label、T2 action label 或新的模型/裁决结果；PDF、解析和
    manifest 完整不等于 taxonomy 有效、routing 有用或 submission-ready。

- 下一步：
  - 作者签署 T1 guideline、reviewer 资格/独立性与伦理/补偿记录，允许分发后由两位
    真人完成 calibration/evaluation；不增加同模型 vote。
  - T1 gold 冻结后、任何 T2 action label 前，冻结独立 action oracle、
    `binary_raw_difference`/`binary_canonical_difference` 等 comparator、workload
    unit、冲突 recall 和样本量/检验方案。
  - 若 T1/T2 未过门禁，转为 taxonomy/identifiability failure study；若通过，再开始
    JSS 正文。T3 只在保留正向 adjudication 主张时启动，T4 默认删除。

## 2026-08-25：完成 JSS V3 零人工 routing 门禁与 prepare-only 双人材料

- 本次完成了什么：
  - 在权威环境核对 `hostname=code-defender`、
    `pwd=/home/xiaoyuliang/code/vuln-adj` 后，从干净的
    `codex/literature-framing-20260824@5a0238750600e9eef78d3eb39c3d3810df5cd1d7`
    新建隔离分支 `codex/jss-v3-routing-precheck-20260825`；未修改 `main`，未
    push。
  - 在任何真人标签之前冻结五个 maintenance actions、七个策略和主比较：强字段
    简单策略 `field_aware_simple_v1`、type-first 当前效率臂
    `type_first_current_v1`、type-first abstention 安全臂
    `type_first_abstention_v1`；raw/canonical non-equal 降为下界参考。
  - 对 8,066 行、32,264 个四字段实例完成全量 label-free action census、pairwise
    disagreement、conflict-queue/total-manual-route 计数和固定 120 行预算的
    identifiability capacity。独立 verifier 从原始 field view 重算并核对主结果。
  - 零人工门禁返回 `CONDITIONAL_GO_FOR_V3_PACKET_DESIGN`。该结果只授权设计
    packet，不授权 correctness、superiority、workload reduction 或投稿主张。
  - 冻结 V3 action-first/reason-second 协议。两位不同真人标相同的 20 个校准和
    120 个正式案例；动作阶段完整返回并哈希锁定后，才允许发原因阶段。跨标注者
    action×reason 为主要关联证据，同人关联只作上界。
  - 正式样本固定为 severity 50、affected_versions 50、published 10、references
    10；先按稳定 SHA-256 rank 选正式集，再从剩余总体构造 20 行校准集。每个正式
    sampling cell 记录 `N_h`、`n_h`、inclusion probability 和 sensitivity weight。
  - 生成 reviewer A/B 独立顺序、action/reason 分阶段 JSONL/CSV、140 行内部 frame、
    140 行 sealed mapping、role record、stage-lock record 和全文件哈希 manifest。
    V2 未修改，保留为历史 prepare-only 材料且不得用于当前分发。
  - 同步 JSS paper brief、argument plan、claim/evidence ledgers、submission blockers、
    paper state 和总计划，将主张改为“强基线下的效率—安全 frontier”，不再预设
    type-first+abstention 能降低总人工量。

- 产物路径：
  - `experiments/rq2_discrepancy_typing/T1_ROUTING_PRECHECK_PROTOCOL_V1.md`
  - `experiments/rq2_discrepancy_typing/analyze_t1_routing_precheck.py`
  - `experiments/rq2_discrepancy_typing/verify_t1_routing_precheck.py`
  - `results/jss/t1_routing_precheck_v1/`
  - `experiments/rq2_discrepancy_typing/T1_HUMAN_VALIDATION_PROTOCOL_V3.md`
  - `docs/annotation_guidelines/t1_action_reason_v3.md`
  - `experiments/rq2_discrepancy_typing/build_t1_human_validation_packet_v3.py`
  - `experiments/rq2_discrepancy_typing/validate_t1_human_validation_packet_v3.py`
  - `data/annotations/rq2/t1_human_validation_v3/`
  - `paper/jss/PAPER_BRIEF.md`
  - `paper/jss/ARGUMENT_PLAN.md`
  - `paper/jss/CLAIM_LEDGER.md`
  - `paper/jss/EVIDENCE_LEDGER.md`
  - `paper/jss/SUBMISSION_BLOCKERS.md`

- 如何验证：
  - label-free analyzer 返回
    `rows=8066 field_instances=32264 decision=CONDITIONAL_GO_FOR_V3_PACKET_DESIGN`；
    独立 verifier 返回 `rows=8066 action_differences=2332` 和相同 decision。
  - routing precheck 聚焦测试 `9/9` 通过；V3 builder/validator 聚焦测试 `10/10`
    通过；新增核心脚本通过 `py_compile`。
  - V3 normal validator 返回 PASS：calibration `20`、evaluation `120`、
    `distribution_allowed=false`、`human_labels=0`。加
    `--require-distribution-ready` 时按预期以退出码 `2` 拒绝分发。
  - precheck analysis SHA-256 为
    `47428580744f0d83331c15b82a623a771f40a40d1ddcf59731fd83787553f7a8`；
    V3 manifest SHA-256 为
    `f98c9084071cf8c78f4fec977449ff57f5a940fa5c8fa3a3bf19de185c67dfa9`。
  - 校准 proxy coverage 为 deterministic statuses
    EQ/RD/INC/TD/FC=`3/6/5/3/3`；冻结策略输出所覆盖的
    abstain/conflict/enrich/no-action/wait cases=`4/3/9/9/3`。这些只是校准覆盖
    proxy，不预填或规定真人答案。

- 当前观察：
  - simple 与 abstention-aware 主比较共 2,332 个 action differences：severity
    263、affected_versions 1,766、published 0、references 303。真正的增量信号
    主要集中在 affected_versions；published 是构念控制，不是策略优越性字段。
  - 在全语料策略输出上，安全臂比 simple 少 74 个 `conflict_escalation`，却多
    950 个 `conflict_escalation + abstain`。因此“减少冲突队列”和“减少总人工
    路由”方向相反；论文必须报告 frontier，不能把 abstain 当零成本。
  - `type_first_current_v1` 仍是可检验的效率臂，abstention 版本是安全臂。同一
    120 行真人 action 可以同时比较三臂，不增加真人标签量。
  - 正式样本的最大 action-disagreement capacity 为 110；这只是可识别性容量，
    不是 realized power、正确率或预期效应。

- 还没验证的点：
  - V3 guideline 仍为 draft；两位真人尚未招募，身份、独立性、从业者资格、补偿、
    伦理/招募处置和作者分发批准均为空。现实人工标签仍为 0。
  - return importer、完成度/阶段锁 validator、Krippendorff alpha 与三策略配对
    evaluator 尚未实现和冻结；因此当前 packet 不得分发。
  - label-free census 不知道哪种 action 正确，也没有测量用时、成本或真实维护流程；
    不能据此称 type-first 更安全、更省人或更适合部署。
  - JSS 正文、作者元数据、当前 venue requirements 和最终 artifact gate 均未完成；
    投稿状态继续为 `NO_GO_FOR_SUBMISSION`。

- 下一步：
  - 在 reviewer 看到任何材料之前，实现并冻结 V3 return/import、stage-lock、
    pre-adjudication agreement、paired policy comparison 和 blinded adjudication
    sensitivity evaluator。
  - 作者批准 guideline，确认两位不同真人及角色口径，补齐伦理/招募和分发记录，
    再生成单独、可审查的 distribution manifest revision。
  - 先做 20 行独立 calibration action→lock→reason；仅按冻结的 0.60 calibration
    门禁决定是否澄清 guideline，绝不改 120 行正式 selection。之后再启动正式
    action→lock→reason。
