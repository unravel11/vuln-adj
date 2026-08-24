# JSS Framing 与实验缺口审计（2026-08-24）

## 1. 当前判定

**投稿状态：`NO_GO_FOR_SUBMISSION`。**
**方向状态：`CONDITIONAL_GO_FOR_JSS_FRAMING`。**

项目不是“完全没创新”，但最容易写的创新已经被相关工作覆盖。现阶段最有机会成立的 framing 是：

> We study whether action-oriented, field-specific discrepancy types can route maintenance decisions for aligned NVD–GHSA records more efficiently than treating every non-equal pair as an undifferentiated conflict, while explicitly preserving abstention and identifiability limits.

中文含义：研究对象不是“发现数据库有差异”，也不是“自动选出真值”，而是验证**字段专用差异类型是否能作为维护动作的路由层**；系统允许拒判，并公开哪些字段/案例无法由现有证据识别。

## 2. 为什么只能这样 framing

VIEM、TOSEM aspect-level、VuldiffFinder 和 2025 LLM work 已覆盖漏洞信息抽取与差异检测；Cleaning NVD 覆盖字段质量与自动修正；CRH/Truth Discovery 覆盖通用冲突消解；HSC/Learning to Defer 覆盖拒判和转交。因此不能主张“首次差异检测/类型化/拒判/真值发现”。

本项目的剩余资产是：同一 CVE 下已对齐的结构化 NVD–GHSA pair、字段专用合同、完整 provenance/failure ledger、可明确映射到维护动作的候选五类，以及大量 no-go 证据。这个组合有 JSS 的 empirical software/data-management 味道，但只有在真人构念和系统效用上过门禁，才不只是工程整理。

## 3. 贡献上限

| 贡献候选 | 当前证据 | 允许写到哪里 | 还缺什么 |
|---|---|---|---|
| 多字段差异分布 | 冻结 8,066 对；deterministic baseline | 样本内规则输出分布 | 不得写 prevalence truth；需真人估计标签误差 |
| 五类 taxonomy | 规则、AI candidate、prepare-only T1 | candidate construct | 两位真人独立标签、agreement、uncertain、误差分析 |
| action-oriented routing | 只有 argument plan | motivation/candidate design | T2 独立 action oracle 与 binary comparator |
| evidence adjudication | severity 局部诊断；affected no-go | failure/identifiability analysis | 若写正向贡献，需 T3 human-gold 与强 baseline |
| temporal generalization | strict event-time cohort = 0 | 数据可用性限制 | 合格 post-freeze 双边 cohort；否则删除主张 |
| artifact/provenance | 大量 validators/manifests | 可复现性与审计性 | 不得替代科学有效性或投稿 readiness |

## 4. 必做实验 T1：taxonomy construct validation

T1 仍是第一门禁，现有 V2 prepare-only 协议方向正确：两位不同真人、baseline-blinded、50 条 calibration、250 条 evaluation、保留 `uncertain`、作者裁决在 baseline unseal 前完成。开始分发前还必须完成 guideline 签署、reviewer 资格/独立性、角色和伦理/补偿记录。

T1 至少报告：

- 每字段与总体 label distribution，不能只报 pooled accuracy；
- raw agreement、Cohen’s kappa 或适合多类/不平衡的 agreement，同时给 bootstrap interval；
- `uncertain` 和分歧率，不得删除后只算容易样本；
- baseline 对 human adjudicated gold 的 macro-F1、每类 precision/recall、confusion matrix；
- 逐字段错误机制，特别是 references resource identity、severity vector/version、affected_versions package/range 与 TD event-time；
- taxonomy 与 TOSEM 的 expression variation / absence / mismatch 标签的映射表，说明真正新增和无法映射之处。

**T1 go gate 建议在看标签前冻结**：不要只用一个 kappa 数阈值。至少要求 FC 具备可识别的支持、关键类不是由单个 reviewer 单方面产生、`uncertain` 不被压成确定类、以及五类合并/拆分决策由错误结构而非追求指标决定。若 EQ/RD/INC/TD/FC 不能稳定区分，应诚实合并 taxonomy 或改写为 failure study。

## 5. 必做实验 T2：routing utility

T2 是 action-oriented framing 的决定性实验。当前最大风险是 action map 循环定义：若直接规定“RD=去重、INC=补全、TD=等待、FC=人工”，再用同一 taxonomy 计算节省，结论是设计产物而非经验结果。

更可靠的冻结方案是：在 T1 gold 完成后，另由未见 taxonomy 输出的真人 reviewer/curator 仅根据原始 pair、字段上下文和固定 action rubric，独立选择实际动作与是否需要升级；或用真实维护任务记录形成 action oracle。之后再比较 routing policies。

主 comparator：

1. `binary_raw_difference`：所有 raw non-equal 均升级；
2. `binary_canonical_difference`：规范化后 non-equal 均升级；
3. `type_first_current`：基于五类的动作；
4. `always_manual` / `abstain_all`：成本/风险边界；
5. 可选 field-specific simple policy，不应只与最弱 baseline 比。

主指标：FC/conflict escalation recall、漏升级数、unnecessary escalation、每个正确处理动作的人工分钟/操作数、selective coverage、确定子集的 action accuracy、`uncertain` workload。需要同时展示总量和各字段，避免 references 的大量简单行掩盖 affected_versions 失败。

样本量与检验应在 T1 gold 揭封后、T2 action label 采集前，仅根据冻结的 effect unit 和目标最小差异计算并封存。当前 250 行是否有足够 discordant actions 尚未知，不能预先承诺显著性。

## 6. T3、T4 是否还做

**T3 adjudication**：只有论文仍主张“对 FC 选择可信值”时才必做。severity 至少比较 `prefer-NVD`（Bayesian CVSS 构成强反例）、`prefer-GHSA`、`prefer-latest`、evidence score 与 `abstain-all`；affected_versions 必须正面对比已发表 benchmark/工具路线或降为 failure analysis。现有 affected_versions no-go 和同模型标签不能支持正向方法增益。更稳的初稿可把 RQ3 改成 identifiability/failure boundary，而不承诺通用 adjudicator。

**T4 temporal generalization**：当前严格 event-time cohort 为零，继续保持删除主张的默认。只有既有冻结规则下出现足量双边 post-freeze CVE 时再做；不得用 collection-time later 或 snapshot-external 代替 event-time generalization。

## 7. 还缺的非实验材料

- 一张 frozen task/data card：来源快照、对齐率、字段缺失、过滤与 lineage；
- taxonomy 与最接近工作标签的明确 crosswalk；
- 完整 baseline implementation manifest 和运行成本；
- 真人 recruitment/qualification/ethics/compensation 记录；
- JSS 正文、精简后的主文/附录边界、当前 author requirements；
- CVSS Bayesian 全文补读，以及 2025–2026 preprint 出版状态刷新；
- artifact 中可独立重算 T1/T2 表格与图的最小包。

## 8.  venue 判断

**首选仍是 JSS，但仅在 T1+T2 过门禁后。** JSS 已发表漏洞数据库系统映射，说明读者与问题域匹配；项目的长处是 empirical protocol、data lineage、decision utility 与 failure boundaries，而不是一个安全检测算法。

**IST 是务实备选。** 如果 taxonomy/action study 结果清楚但方法理论较轻、篇幅需要压缩，IST 更匹配实证工具/流程贡献；实验门槛不能因此降低。

**Computers & Security 暂不优先。** VuldiffFinder 已直接占据漏洞不一致检测主题；除非 T3 有可复现的安全运营收益或可信 adjudication 增益，否则重叠风险高。

**SANER/FSE/ICSE 不作为当前主路线。** 已揭封的大量开发实验不适合包装成 Registered Report；会议路线若只保留 T1/T2 可能体量合适，但需要重新按会议贡献和时限设计，不应从 27k-word 历史稿直接裁切。

## 9. Go/No-Go 决策树

1. T1 未证明 taxonomy 可由真人复现：`NO_GO` 正向 taxonomy；转 failure/measurement paper 或合并类别。
2. T1 通过、T2 无 routing utility：`NO_GO` action-oriented claim；最多报告 construct 与差异分布。
3. T1/T2 通过、T3 仍失败：可投 JSS 的 typing/routing/failure-boundary paper，不写自动真值裁决。
4. T1/T2/T3 均有独立 human-gold 支持：再考虑更强的 adjudication framing 和 COSE/安全 venue。

## 10. 最小可执行顺序

先完成并签署 T1 真人门禁，不再增加同模型 vote。T1 gold 冻结后更新 taxonomy/crosswalk，随后在任何 T2 action label 前冻结 action rubric、独立 reviewer、comparators、effect unit 和 analysis。T2 完成后再决定正文是“正向 routing”还是“taxonomy/identifiability failure”。在这个决策前，不启动新的 affected_versions 机制开发，也不承诺投稿日期。
