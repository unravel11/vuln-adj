# 项目总计划

**更新时间**：2026-08-24

---

## 当前状态

| 阶段 | 状态 |
|------|------|
| A：仓库与研究资产落盘 | 已完成 |
| B：原始数据收集、清洗与对齐 | 已完成 |
| C：统一字段视图与差异检测 baseline | 已完成 |
| D：标注规范与金标建设 | **进行中** |
| E：证据驱动裁决实现 | **进行中** |
| F：实验汇总与论文写作（JSS 保守重构） | **进行中**（`S1_EVIDENCE_LOCKED`；T1/T2 待完成；COSE 稿转为历史证据线） |

---

## 投稿策略

```
T1 双真人 taxonomy 验证
        ↓ 通过构念门禁
T2 binary-vs-type-first 决策效用
        ↓ 有可报告结果
JSS（主路线，条件式）
        ↓ 体量或契合度不合适
IST（务实备选）
```

- **当前主路线：JSS**。framing 是 NVD–GHSA 字段级差异的
  action-oriented type-first routing、abstention 与可识别性/失败边界，不再主张
  “首次发现漏洞数据库差异类型”。
- **IST** 是完成同一核心实证后、按体量和期刊契合度决定的备选，不是降低实验门槛。
- **SANER Registered Reports** 只适用于另起的、结果尚未揭示的未来确认性阶段；
  不能包装已经揭封的当前实验。
- **暂不优先 COSE/FSE/ICSE/TOSEM/TSE**。现有 COSE 稿保留为历史证据线和
  失败分析来源，不作为当前可投稿稿。
- 历史 `plan_b_cose.md` 与 `plan_a_fse_icse.md` 继续保留，但不再决定
  2026-08-23 之后的主动投稿顺序。

当前投稿判定为 `NO_GO_FOR_SUBMISSION`。只有 T1/T2、JSS 正文、当前格式要求、
作者元数据和最终 artifact gate 全部完成后，才允许重新评估。

### 2026-08-23 JSS framing 与实验边界

- RQ1：报告冻结 8,066 对 NVD–GHSA 记录上的字段级 deterministic distribution；
  不把规则输出写成真值或数据库质量。
- RQ2：由两位不同真人在 baseline-blinded packet 上验证
  `EQ/RD/INC/TD/FC/uncertain` 构念与 baseline；CWE 仅作补充字段。V1 在
  人工标签前因历史 seed 有 2 行上下文漂移而停止；V2 已从当前 field view 重抽
  300 行并生成 50/250 prepare-only A/B packets，当前
  `distribution_allowed=false`。
- RQ3：比较 binary escalate-all 与 type-first routing 的 conflict recall、
  unnecessary escalation、workload 和 abstention；现有 affected_versions 方法结果
  只作为有边界的 no-go/failure evidence。
- T1、T2 为正向 JSS framing 的必需实验；T3 仅在保留正向 adjudication
  贡献时必需；T4 temporal generalization 默认删除，除非出现符合既有冻结规则的
  新双边 post-freeze cohort。
- 完整权威入口：
  `paper/jss/PAPER_BRIEF.md`、
  `paper/jss/EVIDENCE_LEDGER.md`、
  `paper/jss/CLAIM_LEDGER.md` 和
  `experiments/rq2_discrepancy_typing/T1_HUMAN_VALIDATION_PROTOCOL.md`。

### 2026-08-24 仓库整理阶段

- 状态：`COMPLETED`。本阶段只整理 Git 边界和历史资产，不产生新的科学结果。
- 在 `codex/repo-hygiene-20260824` 上分步提交，不直接清洗 `main`，也不自动推送。
- 源码、测试、协议、prompt、论文源文件和小型控制 manifest 进入 Git。
- raw/processed 数据、results、外部论文 PDF、evidence cache 与历史生成 payload
  保留在权威机器，通过精确 `.gitignore` 和逐文件 SHA-256 清单管理。
- 删除范围仅限可再生缓存、操作系统垃圾和误生成命令片段；历史科研 payload
  未经单独证据审计不删除。
- 整理前恢复包：
  `/home/xiaoyuliang/archives/vuln-adj-pre-hygiene-20260824T104541+0800`。
- 完成门：范围受控提交、payload manifest 复核、Python/test validators、
  `git diff --check`、`git fsck` 和 clean worktree 全部通过。
- 整理后 Git 只跟踪源码、协议、文档、论文源文件和小型控制 metadata；
  `4,361` 个本地 payload 文件（`2,296,239,806` bytes）由
  `docs/repository_hygiene/retained_local_payloads.sha256.tsv` 绑定。
- 明确删除 9 个 Python cache 目录、2 个零字节旧锁、1 个 `.DS_Store` 和
  1 个误生成命令文件；删除候选另有可恢复 tar，不包含科研 payload。
- 历史 COSE readiness 的大小写重复已收敛为被代码和文档实际引用的
  `paper/cose/submission_readiness.md`。

### 2026-08-24 相关工作与 framing 资格审计

- 状态：`COMPLETED`。本阶段只核对公开文献证据、数据集、同任务 baseline 与
  当前项目差异，不产生新的实验结果。
- 权威执行分支为 `codex/literature-framing-20260824`；下载和 PDF 核验在
  `code-defender:/home/xiaoyuliang/code/vuln-adj` 进行，不自动 push。
- 先复核现有 16 篇 PDF，再补最接近的字段差异、漏洞元数据质量、冲突消解、
  选择性预测/拒判、人工路由和公开数据集工作。
- 每篇建立独立中文解析，明确全文/摘要/metadata 证据等级、问题链、机制链、
  实验证据、局限以及对本项目可引用与不可引用的边界。
- 总结文档必须比较“已有能力、缺失能力、与本文重叠风险、可复现资源”，并据此
  重审 action-oriented type-first routing framing 以及 T1/T2/T3 的必要性。
- 完成门：可获取 PDF 均有格式、页数和 SHA-256 核验；每个纳入条目均有独立解析；
  跨论文矩阵和 framing 判断落盘；下载失败和证据不足显式保留；总计划与进度日志同步。

---

## 核心数据

- NVD 规范化记录：100,032 条
- GHSA 规范化记录：28,785 条
- CVE-ID 对齐结果：**8,066 对**
- 当前 baseline（2026-07-15 input-integrity refresh）：见 `project_progress_log.md`

---

## 实验进度汇总

| 研究问题 | 当前可核查产物 | 当前进度 | 结论边界 |
|------|------|------|------|
| RQ1：字段差异分布 | `8,066` 对 NVD-GHSA 匹配记录、全字段差异统计、matched-row 覆盖率；已过滤 NVD `vulnerable=false` CPE 并完成输入完整性诊断 | 描述性数据链路已完成；本次过滤涉及 `106/8,066` 条记录并改变 `10` 条 affected_versions baseline 分类，当前该字段为 EQ `425`、RD `3,936`、INC `3,054`、FC `651` | 可报告样本内分布与输入修复影响；不能把规则输出当成已验证真值 |
| RQ2：差异类型检测 | AI expert candidate primary `300/300`、same-model consistency `60/60`；CWE 17 条与 References 56 条完整影响面审计；fresh-CVE typing stability `1,250` 行 A/B 双 pass；profile seal 后另采集官方 2026 snapshot 并冻结 `250` 行 snapshot-external A/B cohort；对旧 cohort 的 103 条非严格行完成 reviewer C tiebreak，并对剩余 37 条完成冻结 URL evidence 的 D/E 双审；对新 cohort 的 3 条 CWE profile difference 完成冻结 9 个 URL 的 evidence-secondary 双审，把同一证据合同扩展到全部 50 条 CWE，并对原 19 条 A/B 未决中的其余 16 条非 CWE 行完成最终冻结证据 G/H 双审；旧 1,250 行与新 250 行均已有盲化现实人工三阶段包；另有 calibration、graph 机制、无标签 paired-outcome envelope、exact paired-test identifiability、5,948-CVE eligible-universe prediction census，以及第二次 label-free official acquisition delta | 旧 fresh A/B strict `1,147/1,250`，经 C 与 D/E 后 combined candidate 为 `1,219/1,250=0.9752`，frontier 状态 `stop_same_model_escalation_no_go`。新采集的 strict event-time 层为 `0`，snapshot-external eligible 为 `5,948`；固定抽样 250 条后，A/B exact `236/250=0.9440`、kappa `0.9250`、strict `231/250=0.9240`。密封主评估中六个 profile 只有 3 条 CWE/combined prediction 不同，仅 1 条差异形成 strict consensus，current 为 `185/231=0.8009`，CWE candidate 为 `186/231=0.8052`。事后 3 条定向审计为 `3/3` candidate direction；全 50 条 CWE 双审 strict 为 `49/50`，current/candidate 为 `45/49` 与 `48/49`。最终非 CWE 阶段虽有 `16/16` 证据可用，但仅 `4/16` strict（affected_versions `2/12`、references `2/2`、severity `0/2`）；staged candidate 为 `238/250=0.952`，因 selected-row resolution `0.25<0.40` 返回 no-go。无标签枚举证明只有 3/250 行能改变 paired result，完整 cohort accuracy difference 绝对值上限为 `0.012`；125 种标签分配中 `0/125` 能使双侧 exact McNemar 在 `alpha=0.05` 下显著，最小可达 p 值为 `0.25`。完整 eligible universe 的 29,740 个字段实例上，六个 profile 各自形成独立预测向量，但 union 只有 34 个差异 CVE：CWE `29`，references original/audited `5/3`，combined original/audited `34/32`；250 行回放完全一致。第二次采集的 NVD 从 `34,056` 增至 `34,130`，其中 `39` 条为冻结后新发布，但 reviewed GHSA 冻结后新增为 `0`；单一 GHSA 匹配仍为 `5,948`、field view byte-identical、strict event-time 仍为 `0`，因此不冻结新 cohort。production default 不变；旧/新人工包分别为 `1,250 pending / 0 signed` 与 `250 pending / 0 signed` | 新 cohort 不是 strict event-time cohort。A/B 与 evidence reviewers 均属同模型相关 pass；全 50 条与最终 16 条审计均是揭封后的选择性字段诊断，`238/250` 不能写成 accuracy，`191/238` 对 `188/238` 的差异也完全继承自此前三条 CWE。无标签包络、exact-test 枚举、eligible-universe census 和第二次 acquisition delta 都不是 correctness 或 accuracy evaluation。全量普查纠正了把分层样本 `3/250` 当作总体稳态率的假设，但 34 条预测差异不等于 correctness discordance 或 candidate win；该快照已揭封，也不能估计未来 prevalence。第二次采集只定位到 GHSA 尚无冻结后发布记录的双边可用性瓶颈，不能据此宣称 temporal validation。不能据此宣称 confirmatory gain、future-snapshot generalization、human-gold accuracy 或 production switch。现实人工签收仍为 0 |
| RQ3：证据驱动裁决 | severity AI gold `80/80`（风险复核 `51`）；affected_versions 旧开发集、v1 holdout 和新 v2 holdout 均已有可核查 evidence/reviewer/consensus 产物。v2 排除前两批共 200 个 CVE，从剩余 `451` 条候选中冻结 `100` 条；盲文件、300 条类型预测、1,900 条来源预测和协议代码均在双 Codex review 前封存 | severity 有 `79/80` 条确定样本，evidence-score accuracy `0.7215`。v1 严格联合确定 `35/100`，其 post-hoc FC-only 结果未超过固定来源。v2 标签/Artifact 精确一致为 `65/100`、`80/100`，kappa `0.5353/0.6690`；严格类型 `41/100`，其中 FC `15`、INC `8`、RD `18`。严格 FC 中来源确定 `9/15`，source kappa `0.4079`。预注册类型主方法仅覆盖并命中 `3/41`，full accuracy `0.0732`，低于 legacy `16/41`；来源主方法 branch graph 为 `2/9`，低于 prefer-NVD `6/9`。揭封后按 Phase D/v1/v2 留一 cohort 训练的结构化模型在类型 pooled 为 `70/118`，但留出 Phase D 时仅 `22/42`，低于 legacy `27/42`；来源 pooled 最好 `19/45`，低于 branch `27/45`。两个端点的稳定提升门槛均失败，现实人类签收仍为 `0` | v2 把 typing 与 FC source 设为独立端点，修复了 v1 的任务混评，但标签仍来自同模型家族 Codex，不是 human-gold；严格来源只覆盖全 cohort 的 `9%`。post-hoc authority/type 候选和留一 cohort 模型均未跨 cohort 稳定超过命名基线，因此不启动 v3、不切换生产默认。当前证据支持可审计协议、证据依赖与失败分析，不支持 affected_versions 方法增益 |
| 论文与复现包 | COSE 稿件、表格生成器和 package validator 已存在 | 进行中，`submission_ready=false`；已纳入 staged frontier/provenance stop rule、lineage graph、多个机制 no-go、post-profile snapshot-external 双 pass、三条 CWE case diagnostic、全 50 条 CWE field-control diagnostic、最终 16 条非 CWE evidence no-go、无标签 paired envelope、exact paired-test identifiability、eligible-universe prediction census、完整 34 条 prediction-difference 字段专用审计、第二次 label-free acquisition delta 和两套 full-cohort 人工 blocker；重建 Markdown 原始 `wc -w=27,050`，SHA-256 `dbc018bc...b720`。权威远端完整 rerender、LaTeX 编译、日志与 88 页联系表检查现为 `127/127` 通过，PDF SHA-256 `15d758b0...4b95`，claim-boundary lint 通过 | 仍缺 human-gold 和投稿元数据；正文已明显过长，应把机制细节移入附录并按期刊口径压缩；最终人工实证修改后还需重新编译和作者版式复核 |

**2026-07-19 状态补充：** eligible-universe 的完整 34 条 prediction-difference union 已按字段拆分并完成两套独立非人工审计。CWE 为 strict `26/29`，candidate/current/neither/unresolved=`25/1/0/3`；references 的 complete partition 在 underlying/HTTP 两定义下 strict=`1/5` 与 `3/5`。references v1 因 merge writer 缺失在任何 result 输出前失败并归档，v2 重新 seal、重新双审后通过独立 verifier。两套结果均是 census 揭封后的 outcome-selected same-model 诊断，sealed 250-row evaluation、production default 和现实人工队列均不变。论文包随后在权威远端通过 `127/127` checks；88 页联系表现绑定当前 PDF 哈希、独立页数和精确页序列，修复了旧验证顺序允许构建后联系表失效的问题。第二次官方采集又以 label-free delta 验证 NVD 已出现 `39` 条冻结后新发布记录而 reviewed GHSA 为 `0`，strict event-time 仍为 `0`；独立 verifier 通过且不冻结新 cohort。

## 主要论文贡献与证据状态

| 计划贡献 | 当前证据状态 | 投稿前必须补齐 |
|------|------|------|
| 定义 CVE 对齐后的字段级差异检测与裁决任务 | 已有 NVD-GHSA 数据链路和 RQ1 描述性统计支撑 | 固化问题定义、分母和适用范围，避免从样本分布外推数据库质量 |
| 提出 EQ/RD/INC/TD/FC 五分类体系及字段规则 | taxonomy、规则 baseline、标注规范和 RQ2 AI candidate 已实现。旧 fresh A/B、C tiebreak 和 D/E evidence stage 形成逐级 fail-closed 链路并由 staged frontier 给出停止同模型升级的 no-go。profile seal 后官方快照把 event-time 与 snapshot-external 资格分开：strict event-time 为 0，5,948 个 snapshot-external CVE 中冻结 250 条双 pass，得到 231 条 selective strict candidates；密封主评估仍只有 1 条 strict profile difference 支持 candidate。事后 3 条与全 50 条 CWE 审计分别得到 `3/3` 与 `49/50` strict；最终 16 条非 CWE 冻结证据双审只有 `4/16` strict，staged coverage 虽为 `0.952` 仍因 resolution 门槛失败。无标签 paired envelope 将任何未来 gold 下的总体准确率差界定在 `±3/250=±0.012`；exact-test identifiability 证明当前三条差异没有 `alpha=0.05` 的检验容量。完整 eligible universe 的 prediction census 又得到六个独立预测向量但仅 34 个差异 CVE，并证明分层样本的 `3/250` 不能直接作为总体率。lineage graph 另把 affected 拆为 artifact identity、product dependency、migration、release ordering、branch ancestry、catalog coordination 和 set containment。当前贡献是可审计 taxonomy、预密封预测、时间资格分层、证据合同、provenance/frontier stop rule、可识别性/效应与检验容量上界、全量预测普查和拒判/恢复门禁，不是已验证规则准确率提升 | 不再把已揭封字段或差异子集上的同模型 evidence pass 当作确认。现实人类需签署旧全量 1,250 行包、新 cohort 250 行包、CWE 17 行与 References 56 行，并优先复核新 cohort 的原 19 条 A/B 未决、3 条 profile differences、最终仍未决的 12 条和 CWE field-complete 的 1 条未决。后续 strict cohort 应先冻结 profile 并对 eligible universe 做 prediction census，再把分歧富集 paired comparison 与概率抽样 absolute evaluation 分层；gold 后有效 discordance 和 exact power 必须单独规划。只有 construct 与现实人工门禁通过，才允许确认性比较或生产候选切换 |
| 提出带 abstain 的确定性证据驱动裁决框架 | RQ3 已把不确定性、证据 provenance、盲 worklist、预测预密封、双 Agent 独立性门禁和拒判显式落盘。v1 暴露任务混评；v2 随后预注册独立 typing/FC-source 端点、结构化 literal-quote 证据和代码哈希门禁，并再次得到低覆盖/无方法增益结果。v2 strict type coverage 为 `41%`，strict FC-source 仅为 `9%`；其中 9 条来源共识有 5 条由两位 reviewer 引用同一个 URL，只有 2 条由双方都引用 primary/ecosystem evidence。揭封后的候选和留一 cohort 模型均未通过稳定提升门槛 | 当前可贡献的是可审计评估框架、拒判机制、任务拆分、证据依赖审计和 failure/protocol taxonomy，不是已验证有效的 affected_versions 裁决算法。后续优先补现实人类金标和来源权威合同；在跨 cohort 门槛通过前不消耗新 v3，任何未来确认性方法仍需独立新 cohort |
| 构建字段级检测与裁决评测集 | 模板、AI expert candidate、风险工作集、交互式 Codex 裁决账本、不可伪装 human-gold 的 schema/guard、两个 CVE-disjoint holdout，以及一个 prediction-sealed `250` 行 snapshot-external development cohort 均已落盘；CWE 17 条、references 56 条、fresh-CVE typing 全部 1,250 行和 post-profile 全部 250 行均有 annotator→独立 reviewer→author sign-off 三阶段空白包 | 现实人类 annotator、独立 reviewer 与 author sign-off；旧 typing 包当前 `1,250 pending / 0 signed`，post-profile 包 `250 pending / 0 signed`，CWE 包 `17 pending / 0 signed`，references 包 `56 pending / 0 signed`。package validator 已将两套 full-cohort readiness 纳入独立 blocker，空白包不能通过签署/完成门禁，ID 字符串也不能证明真人身份。全项目现实人类签署仍为 `0`，不能称 human-gold，也不能把 AI/Codex 指标写成最终人工性能 |

---

## 文档索引

| 文档 | 内容 |
|------|------|
| `../../paper/jss/PAPER_BRIEF.md` | 当前 JSS 论文目标、RQ、贡献上限和实验决定 |
| `../../paper/jss/ARGUMENT_PLAN.md` | 当前 S2 候选论证、章节职责和图表计划 |
| `../../experiments/rq2_discrepancy_typing/T1_HUMAN_VALIDATION_PROTOCOL.md` | T1 结果无关双真人标注协议 |
| `plan_b_cose.md` | 历史 COSE 计划，保留作追溯，不再是主动路线 |
| `plan_a_fse_icse.md` | 历史 FSE/ICSE 计划，保留作追溯，不再是主动路线 |
| `project_progress_log.md` | 已完成工作的详细记录（数据、脚本、统计数字） |
| `../related_work_survey.md` | 相关文献综述（含每篇论文与本文的边界分析） |

---

## 当前最紧迫的事

当前最紧迫的事：

1. 作者确认 JSS 候选 title、RQ1/RQ2/RQ3、四个主字段和 CWE 补充字段的边界；
   未确认前保持 `S2 candidate`
2. 作者确认并签署 T1 calibration guideline、两位 reviewer 资格、
   role/independence、ethics/compensation 记录；prepare-only packets 已生成，
   但独立 distribution gate 尚未开放
3. distribution-readiness validator 通过后，两位不同真人独立完成 calibration
   和 250-row evaluation；保留全部
   `uncertain` 与失败字段，完成 author adjudication 后才计算 baseline 指标
4. T1 gold 冻结后再冻结并运行 T2；若 taxonomy reliability 或 downstream
   utility 失败，停止正向方法路线并保留为 construct-ambiguity/negative study
5. 决定 adjudication 是否仍为核心贡献；若是，另冻 T3 真人 severity/affected
   实验；若否，把现有 no-go 移入 bounded failure analysis

以下 2026-07-19 详细队列保留为历史执行与人工包索引；它们不得覆盖上述
2026-08-23 JSS 主线优先级：

1. 从 AI gold 保留的高风险行开始现实人类复核：RQ2 `18` 条 uncertain、RQ3 severity `22` 条 requires review；affected_versions 优先复核 v2 全部 100 条，其中 41 条为严格类型候选、59 条为类型分歧/拒判，且只有 9 条达到严格 FC-source 共识；当前真实签收为 `0`
2. 填写并独立复核 RQ2 canonical primary `300` 条、review `60` 条和 RQ3 human audit `180` 条；AI candidate 覆盖虽已完整，但不能替代这些人工流程
3. 只有通过独立 reviewer、author sign-off 和 `--require-signed`/`--require-complete` 门禁的行，才能进入 canonical human-gold 与 guarded evaluator
4. References 三阶段空白包已把 `underlying_content_resource`、`frozen_http_resource` 和自定义显式口径写入同一校验合同；当前 `56 pending / 0 signed`。现实人工应优先裁决 24 条 encoded-line 双审分歧，再完成全部 56 条 annotator、独立 reviewer 与 author sign-off；32 条非人类严格共识和 audited profile 均不能替代签收
5. v1 和 v2 holdout 均已揭封，禁止再用它们调参后声称独立验证。揭封后的 authority/type 候选与留一 cohort 模型均未跨三个 cohort 稳定超过命名基线，当前不启动 v3；下一步优先完成现实人类复核和来源权威合同，只有开发诊断先通过跨 cohort 门槛后，才考虑冻结新的确认性 cohort
6. CWE taxonomy 的 17 条完整影响面第一轮严格共识为 `11/17`；对原 9 条高风险行增加冻结引用后，第二轮严格一致 `7/9`，组合严格覆盖为 `15/17`，但仍不是现实人类。三阶段空白人工包为 `17 pending / 0 signed`；优先人工裁决当前 `2` 条未决和 `4` 条 candidate regression，随后签收全部 17 条；未签收前不批量切换
7. RQ2 37-row evidence secondary 与 staged frontier 已完成并停止旧 cohort 上的同模型升级。profile seal 后官方快照的 strict event-time 为 `0`，snapshot-external cohort 为 `250` 行，A/B strict `231/250`；密封主评估仍为 current `185/231`、CWE candidate `186/231`。解封后的 3 条定向审计为 `3/3` candidate direction；全部 50 条 CWE 审计为 strict `49/50`、current `45/49`、candidate `48/49`。对原 19 条 A/B 未决中的其余 16 条完成最终冻结证据 G/H 双审后，仅 `4/16` strict，staged candidate `238/250`，固定 resolution 门槛失败并返回 no-go；剩余 12 条继续交现实人员。无标签枚举得到最小 p=`0.25`、`0/125` 标签分配显著；完整 5,948-CVE prediction census 则在 29,740 字段实例中只发现 34 个差异 CVE，其中 CWE 29、references original/audited 5/3，并证明 `3/250` 不是总体率估计。新 250 行人工盲包当前 `250 pending / 0 signed`，package validator 已纳入 blocker。下一步是现实人员完成全量签署并等待双边事件时间均晚于冻结点的 strict cohort；未来应先 census 密封预测，再预先冻结分歧富集 paired comparison 与概率抽样 absolute evaluation，不能把本快照的 34 条差异当作 gold、未来 prevalence 或 power，也不再从本快照抽样、增加同模型投票或 promotion
8. 完整差异集审计不解除上述停止规则。CWE 的 `25:1` 条件方向和小 p 值不具确认性；references 的完整分区仅 `1/5` 与 `3/5` strict，也不得按目标 alias 的局部一致事后放宽。现实人工应在既有 250/17/56 行包中处理这些构念分歧，不再为当前已揭封 snapshot 增加第三个同模型 vote
9. 第二次 label-free acquisition delta 已确认 NVD 有 `39` 条冻结后发布记录，但 reviewed GHSA 为 `0`，单一 GHSA 匹配和 field views 均未变化。当前 decision 为 `wait_for_bilateral_post_freeze_records`；只在后续重复同一采集/独立验证后 strict unique CVEs 达到预定最低 `25` 时，才冻结每字段 5 行的新 cohort

---

## 已知风险

- 当前 `affected_versions` baseline 有 `651` 条 FC；NVD `vulnerable=false` CPE 已在上游过滤，但“不同包导致的版本体系不一致”仍未解决，可能继续产生误判
- artifact-lineage cross-case v1 的 `8/8` gate coverage 只来自 raw interval 完全相等、单一 subject 的已揭封 v2 calibration 行；selector 虽不读取 reviewer 文件，但上游 source 本身按非人工 consensus 构建。该结果不能外推到非等边界、multi-artifact、未见生态或真实人工准确率
- 非等边界 graph v1 在固定 released-version catalog 语义下只与 A/B 同时一致 `2/5`：Electron/Jenkins 的当前发布集合相等，但 A/B 按 singleton/list 与 interval 的 intension 判为 `incomplete`；Graylog 的 Maven Central catalog 又缺 prerelease boundary。该 no-go 说明 set relation 在字段合同未选择 extensional/intensional/temporal 语义前不能直接映射 taxonomy
- InLong 多构件诊断只含一个已揭封、同组件范围样本；两个构件集合相同，因此没有验证 component heterogeneity。其 `1/1` projection 和 RD candidate 与两份 A/B 的 INC 标签冲突，只能作为待现实人工裁决的合同压力测试，不能解除非等边界 no-go
- 异构多包未见生态队列直接来自完整 aligned input 且不受 reviewer/consensus 条件化，但固定三例均无法建立 total component→product release map：Oracle 起始边界和产品/package 映射缺失，LangChain 的 numexpr 依赖只有范围约束，Deno 的产品修复边界不在 crate catalog 且 deno_runtime 依赖也只是 caret constraint。`0/3` 是 construct no-go，不是三种 registry parser 的准确率
- Deno lockfile recovery 在 parent no-go 揭封后才设计，虽然新合同先于新的 GitHub/Cargo.lock 证据冻结且独立 verifier 重算通过，但它复用了同一已知 CVE。`71/71` exact mappings、NVD `63` < GHSA `68` 只能证明该单例的机制恢复，不是无偏成功率、human gold、lockfile 普遍权威性或 crates.io 泛化证据
- remaining 28-row edge audit 的 family rules 与结构分数是在全部上游结果揭封后设计，只能分配开发工作，不能估计项目族成功率。Mattermost v1/v2 又在证据接口与 domain 假设上连续失败，v3 才进入 Git-tag graph；其 `19/19` current-module manifests、两个精确 pseudo commits 与 `0/2` projection 证明的是 branch/backport 和 legacy-coordinate 断边，不是 Mattermost 标签真值、Go 生态失败率或 graph 方法准确率
- LF Edge EVE v1 在冻结前已发现 207-tag grammar、nested module/component paths 与 pseudo changed paths，因此明确禁止 candidate promotion。Git pack/verifier 可证明 tag、commit、path 与 ancestry facts，但 API 中的根 package/pseudo 与 repository advisory UI 的 component/product anchors 属于不同证据接口；`0/2` 不能写成 EVE 真值、GHSA 历史错误或 Go repository prevalence
- Hutool v1 在冻结前已发现三个 214-token Maven catalogs 相等、稳定域为 209 tokens，并观察三个关键 aggregate POM/JAR anchors，因此 2/2 mechanism pass 与两条 `incomplete` development candidates 均不得 promotion。该结果只支持当前 snapshot-extensional token correspondence 和 anchor containment；它不证明 209 个历史 aggregate JAR 全量、无上界 advisory 的时间意图、Maven 项目族成功率或 human accuracy
- Hutool external application 排除了 prior-exposure union 中 `1,967` 个 CVE；exclusion parser 只投影 `cve_id`，selection logic 不使用 baseline/reviewer/candidate 字段，并在候选计算前封存 6 条记录。但记录 availability 与 route shape 仍在同一 aligned snapshot 中先被观察。其 `6/6`、INC `5`、RD `1` 只能支持 retrospective mechanism reuse，不能称时间 holdout、外部有效性、coverage gain 或 human accuracy，六条均不得 promotion
- residual non-affected audit 的三条记录是根据 D/E 已揭封后的未决状态定向选择，且证据接口形态在 v1 前已观察；CVE-2024-8020 的 `factual_conflict` 仅为非人工、source-local mechanism candidate，CVE-2023-4304 与 CVE-2023-32187 仍分别受 concrete CWE 与 resource identity construct 约束。`1/3` 不是无偏成功率或 coverage gain，三条均不得 promotion
- staged frontier 是后验、逐级条件化的 operational audit：C 的 `66/103` 与 D/E 的 `6/37` 来自难度不同的 selected sets，不是受控方法比较。三次 B 缺失尝试没有 response-error 或 token usage，账本只能记录 3 个 excess attempts、90 retry row-items 和一个 ambiguous duplicate payload，不能补造错误原因。stop rule 只约束当前已揭封 cohort 的同模型升级，不外推现实人员或未来快照
- post-profile acquisition 发生在 profile seal 后，但 5,948 个 snapshot-external CVE 的 NVD/GHSA normalized published time 都没有同时晚于 seal，因此 strict event-time 层为 0。250 行 A/B 的 `0.9440` exact、`0.9240` strict 及 CWE candidate 的 `+1` strict paired row 只能用于 development；两个 pass 共享模型家族，另外两条 candidate difference 非 strict，不能写成时间外推、确认性方法提升或 human accuracy
- post-profile CWE field-complete 审计是在 A/B 与 profile differences 揭封后选择字段；虽然它覆盖全部 50 条 CWE、把 3 条差异隐藏在 47 条 control 中，并由 20 个互斥 ephemeral sessions 得到 `49/50` strict、current/candidate `45/49` 对 `48/49`，仍不是预注册确认性实验。V1 把 literal subset 错写成固定 `incomplete`，V2 又到 merge 才检查 literal quote，均已整轮排除并封存；V3 的 `+3/49` 只能作构念和协议诊断，不能替换主评估 `+1/231`
- post-profile 最终非 CWE evidence stage 是在 A/B 揭封后选择 16 条困难行。虽然 50 个冻结记录全部抓取成功，G/H 与此前 sessions 互斥，且 hash/request/citation 合同由独立 verifier 重算，仍只有 affected_versions `2/12`、references `2/2`、severity `0/2` strict。`238/250` staged coverage 条件保留 231 条既有 strict 并只从揭封子集增加标签，不是 full-cohort accuracy；`191/238` 对 `188/238` 的差异完全来自此前 CWE stage。固定 `0.40` resolution 门槛以 `4/16=0.25` 失败，因此必须停止同模型升级并保留 12 条未决
- paired-outcome envelope 与 exact-test identifiability 的 125 个 assignments 是五分类逻辑组合，不是等概率标签先验或经验分布；40/40/45 的 candidate/current/tie 计数不得换算成成功概率。`±1.2pp` 只界定 full-cohort accuracy difference；`0/125` 显著和最小 p=`0.25` 只证明当前三条差异没有 paired-test capacity，不证明方法等价。未来 658/771/874 行的 difference-availability 数依赖独立抽样与 `3/250` 稳态差异率，49/20/12 条的 80% power 数又条件于 0.70/0.80/0.90 的 candidate-direction correctness probability，均不是预注册样本量、macro-F1 或构念有效性结论
- eligible-universe prediction census 精确回放 250 行后覆盖全部 `5,948×5=29,740` 字段实例，六个 profile 在全量上各自形成独立向量，但 union 只有 34 个差异 CVE，且无 multi-field difference。该快照已揭封，差异是 deterministic profile outputs，不是 correctness discordance、gold、candidate win 或未来分布估计；它否定直接使用分层样本 `3/250` 的稳态率假设，也不能反过来把 34 当作确认性样本。references original/audited 只有 `5/3` 个潜在差异 CVE，当前 universe 连极端 6 条同向显著性下限都达不到；CWE/combined 的 `29/34/32` 仅表示理论可用差异容量，仍未知 gold 后有效 discordance
- eligible-universe CWE complete-difference audit 虽覆盖全部 29 条变化且 strict `26/29`，但所有行都暴露 disjoint taxonomy relation，选择发生在 census 揭封后，E/F 仍属同模型家族；`25:1` 与 `p≈8.05e-7` 只能描述该 revealed impact set 的条件证据方向，不能写成 accuracy、预注册显著性或 production promotion
- eligible-universe references v2 采用 profile-independent complete partition；underlying/HTTP strict 仅 `1/5` 与 `3/5`。URL 值仍可能暴露 CVE 和 alias class，完整分区又受 NVD/advisory/第三方页面 ontology 影响。v1 merge-code failure 已归档且不进入结果；v2 的 HTTP 三条 `incomplete` 与 p=`0.25` 仍不是 human-gold 或 confirmatory gain
- 第二次 post-profile acquisition 虽在 collection time 上更晚，且 NVD 新增 74 条、其中 39 条为冻结后发布，但 reviewed GHSA 新增/变化/冻结后发布均为 0；因此 strict event-time 仍为 0。该 delta 只能定位双边数据可用性瓶颈，不能作为 temporal validation、future-snapshot generalization 或等待时间分布估计
- RQ2 reviewer C 只覆盖 A/B 揭封后的 103 条非严格行。虽然 worklist 盲化、sessions 与 A/B 隔离且 request log/merge 由独立 verifier 重算，但 A/B/C 仍共享模型家族、prompt 和快照；`66/103` 解决率与 `1,213/1,250` coverage 是选择性 non-human candidate 诊断，不是三位独立专家一致性或 gold-backed accuracy
- 37-row evidence secondary 同样是 A/B/C no-go 后选择的困难子集，D/E 与前三轮共享模型家族；URL selector 只覆盖原 reference context，成功抓取也不等于完整 product/package/range evidence。`25/37` exact 被 `19` 个共同 uncertain 主导，strict `6/37`、affected_versions `0/28` 和 combined `0.9752` 都只能作为 abstention/evidence-boundary diagnostic
- 2026-07-15 输入完整性诊断确认旧语料曾纳入 `1,105` 个 `vulnerable=false` CPE，涉及 `106/8,066` 条对齐记录；修复后 `10` 条 baseline 分类改变。冻结的 100 条 RQ3 affected_versions 样本中有 `7` 条输入变化，但样本映射、40 条确定/60 条拒判分布和所有最终标签均未改变；该结论只说明当前样本复核结果未变，不证明更广泛规则正确性
- 当前 GHSA snapshot 的 `28,785` 条 reviewed records 中未发现单一 range 含多个 event 的情况；现有首 event/首 fixed 展平逻辑因此未污染本次 snapshot，但仍是未来数据更新的潜在输入风险
- 目前没有人工金标，所有 baseline 统计数字都是 deterministic 规则的输出，不是验证后的最终结果
- RQ3 `silver_v2` 是 evidence-aware LLM silver label，不是人工 gold；仍需评估其可靠性并保留 abstain
- Codex 逐条证据裁决可作为 expert-adjudicated gold candidate，但标注者不是人类；未经作者人工复核签收不能报告为 human-gold
- RQ2 与 RQ3 指定模板的 AI candidate 已全覆盖，但全部由 Codex 流程产生；RQ2 复标也是同模型分轮复标，不是独立人工复核
- RQ2 candidate-vs-baseline 的 determinate agreement 为 `0.8834`，同模型复标 agreement 为 `0.7667`、Cohen's kappa 为 `0.7071`；这些数字受候选生成和规则相关性影响，只能作为诊断
- references normalization 变体是在检查 candidate 误差后设计的。旧 URL-only 双 AI pass 虽为 `56/56` 单类一致，但新完整证据双审只有 `32/56` 严格共识、label kappa `0`；24 条 encoded-line 行全部分歧，证明旧单类一致不能替代资源 identity 构念和现实人工签收
- references revision-2 证据双审是在 hidden-contract pilot 失败后修复 prompt/validator 合同；旧 seal/output 已保留并排除，E2/F2 为全新隔离运行，但该修订不能声称在任何模型输出前完全预注册。后续 audited profile 又在完整影响面揭封后选择，只能用于 development diagnostic
- `affected_versions` package/range baseline 在 silver 上的覆盖率仅 `0.45`；立即后继边界只可作为诊断，不能自动证明区间等价；canonical token 的总体 agreement 也没有提升，不能写成已验证的语义裁决方法
- affected_versions 的 `10` 条 raw/canonical 方法分歧盲审中，两个隔离 Agent 对 canonical-match verdict 与匹配策略完全一致，但最终 discrepancy label 仅 `4/10` 一致；这说明“token 命中有效”与“整段范围等价或来源可靠”是不同判断层级
- package-gated contextual canonical 在双 AI 来源共识子集命中 `4/7`，但全体 `100` 条覆盖率仅 `0.34`，silver/candidate agreement 仅 `0.21/0.30`；不能把定向子集表现外推为总体改进
- CWE taxonomy 双 AI 盲审对集合关系和“是否为纯层级差异”的判断均为 `15/15` 一致，但最终 discrepancy label 只有 `10/15` 一致、kappa `0.4898`；官方 ancestor/descendant 路径只能证明 taxonomy 兼容，不能单独证明 CVE-specific 映射正确
- CWE `taxonomy_v1` 在 primary candidate 上从 `45/49` 提升到 `46/49`，在 same-model review 上却从 `12/12` 降到 `11/12`。sealed full-impact 第一轮严格共识为 `11/17`；对 9 条分歧/回退行增加冻结引用后，第二轮严格一致 `7/9`，组合为 `15/17`。seed-disjoint 严格行上 taxonomy/current 为 `10/14` 对 `4/14`，但第二轮是 post-hoc 选择、仅 `28/36` 个引用抓取成功、exact sign diagnostic `p=0.1796`，且两位新 reviewer 仍来自同一 Codex 模型家族。结果方向正向但 impact-selected、证据可用性不均、非人类，不能切换生产默认
- RQ2 AI gold 的风险选择依据包含 baseline/candidate/repeatability 分歧，reference/CWE 规则又是在候选误差检查后设计；`0.9326` 等数字存在同源标注和选择偏差，不能当作独立泛化性能
- RQ2 当前快照 typing stability 队列已排除 717 个既往暴露 CVE，因此六个 profile 的 1,250 行封存预测完全相同。已完成的双 pass 只能估计 baseline typing stability，不能由“无预测差异”推断候选方法无效或有效；A/B 分别由 28/67 个 ephemeral sessions 组成，B 有 3 个合同违规批次被拒绝后重跑，且当前请求日志没有把 validation exception 写成 `response_error`。确认性 candidate 比较仍需要未来新快照
- RQ2 typing failure-mode diagnostic 揭封后才定义：severity baseline 只比较 canonical label，而 reviewer protocol 还比较 score/vector/version；affected_versions 的 package-specific 无界声明又可能被 span projection 擦除。post-hoc profile 在同一 non-human strict 集上的 `1,121/1,147` 只能说明这两个机制解释当前分歧，不能写成泛化提升。全量现实人工包虽已准备为 `1,250 pending / 0 signed`，validator 也不能从 ID 字符串证明真实身份或独立性
- 跨协议回放进一步否定直接升级：severity 新合同相对旧 AI-gold primary/review 分别 `-23/-7`，在 fresh strict 却为 `+165`；affected 旧 seed 的 10 条相关行只保留 package identity、两边 range 均投影为空，而 fresh 25 条保留 raw unbounded claim。不同协议/输入构念的标签不得 pooled，也不能用当前 aligned snapshot 回填旧输入后冒充独立验证
- RQ3 severity AI gold 中 `51/79` 个确定来源标签为 `both`，evidence-score baseline 与标注决策共享相同抓取证据；`0.7215` 只能作为内部一致性诊断
- RQ3 affected_versions 原 AI-gold 有 `40/100` 条确定行；按统一严格双 Agent source 合同重建后只有 `31/100` 条确定 source。任何指标必须明确使用哪个 overlay、证据快照和 coverage，不能混用旧 40/44 行结果或隐藏拒判样本
- 配对 bootstrap 与 exact McNemar 均条件于当前 AI-gold、样本选择和方法开发过程；RQ2 reference/CWE 规则是在候选误差后设计，RQ3 方法与裁决共享证据，因此这些区间和 p 值只能作样本内诊断，不能解释为独立确认性推断
- affected_versions repository crosswalk 将 package-comparable 从 `45/100` 提高到 `56/100`，但 raw crosswalk 在确定 AI-gold 上只提高 coverage、不提高 accuracy，canonical 的 `+5pp` 区间仍包含 0；七方法事后并集仍只覆盖 `23/40`，剩余 `17` 条全为 range-semantic。该结果不证明总体方法上限或因果错误机制
- 修正 cue binding 后，release-boundary extractor 在确定 AI-gold 上为 `22/40`、固定 fallback 为 `23/40`；相对 canonical token 的 `+7.5pp` 区间为 `[-12.5,+27.5]pp`，有 `14` 个改进和 `11` 个回退（exact `p=0.6900`）。branch/release-graph 候选只改动 `4/100` 条，固定 fallback 为 `26/40`，相对上一轮增加 `3` 个命中且没有回退，但这两轮方向都来自旧误例检查。事后并集 `37/40` 不是可部署 selector，也不能作为确认性性能结论
- affected_versions 的 prior-abstain re-audit 在 45 条上精确一致 `36/45`、严格新增 4 条；原确定 40 条按同一合同重跑后精确一致 `29/40`、只接受 27 条，两者组成统一严格 `31/100` overlay。Agent B 曾在 schema 检查时看到首条完整 candidate object，虽声明未把 prior source 当证据，仍不能声称完美盲审
- affected_versions 统一证据快照使 branch raw 改变 `15/100`，并使旧 44 行 cohort 的 branch fallback 命中从 `26` 降至 `19`；这是 evidence snapshot sensitivity 的直接证据。当前全覆盖最佳仅为 raw token `18/31`，artifact v2 为 `16/31`，因此旧 40/44 行上的 branch 提升不能再表述为当前方法性能或稳定泛化
- v1 affected_versions holdout 虽与旧 100 条 CVE 零重叠，但仍条件于现有 deterministic FC candidate miner；它不能验证 candidate generation 的总体泛化，也不是独立 human-gold
- v1 双 Agent 的标签/来源 kappa 仅 `0.2679/0.3919`，严格覆盖 `35/100`。预注册 all-strict source accuracy 又把 `17` 条 RD 和 `2` 条 INC 混入 FC 裁决；post-hoc FC-only 分层后 branch/artifact `7/16` 与 prefer-GHSA 持平
- v2 排除 Phase D 与 v1 共 200 个 CVE，并预注册独立端点，但仍从同一 651 条 deterministic FC candidate miner 条件抽样。标签/Artifact kappa 为 `0.5353/0.6690`，strict type `41/100`；strict FC-source 只有 `9/100`，source kappa `0.4079`，不能静默丢弃其他 91 条后外推
- v2 task-separated type 在严格类型集上仅覆盖 `3/41`，虽然选择性一致 `3/3`，但 full accuracy `0.0732`，相对 all-FC 和 legacy 分别低 `29.27pp`、`31.71pp`；来源主方法 branch graph 为 `2/9`，prefer-NVD 为 `6/9`。样本很小且非人类，当前只支持“低覆盖候选失败”，不支持有效方法或固定 NVD 的一般优越性
- v2 原始 reviewer 输出各有一次纯格式修复：A 将 `unresolved=null` 改为空字符串，B 扩展低于冻结 validator 长度下限的 `source_rationale`；均由原 reviewer 完成且未改标签、来源或证据。字符下限未在 prompt 中显式写明，是需要披露的协议瑕疵
- v2 的 9 条 strict FC-source 共识中，5 条由双方引用同一个 URL，3 条的集体证据仅来自 NVD record，只有 2 条由双方都引用 primary/ecosystem evidence；reviewer 独立不等于证据独立，当前来源标签可能偏向可抓取或共享页面
- post-v2 `task_separated_type_v2_candidate` 在 Phase D/v1/v2 上分别为 `7/42`、`11/35`、`10/41`，authority-filtered source 分别为 `3/20`、`2/16`、`1/9`；两者都不具备跨 cohort 稳定性
- 留一 cohort 的 balanced logistic 类型模型 pooled 为 `70/118`，但留出 Phase D 时 `22/42` 低于 legacy `27/42`；来源模型 pooled `19/45` 低于 branch `27/45`。该分析使用揭封后的非人类标签且特征/模型族为事后选择，只能用于拒绝当前候选，不能用于确认性方法选择
