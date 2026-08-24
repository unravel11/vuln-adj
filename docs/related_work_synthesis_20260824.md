# NVD–GHSA 字段差异研究：相关工作综合审计

**检索截止**：2026-08-24
**证据规模**：24 篇；23 篇全文 PDF，1 篇摘要/元数据级 closed-access 临时解析。
**任务边界**：已按 CVE-ID 对齐的 NVD–GHSA 结构化记录对；主字段为 `severity`、`published/date`、`references`、`affected_versions`，`cwe_ids` 为补充字段。

## 1. 先说结论

现有文献已经充分覆盖了“漏洞信息会不一致”“可以自动检测差异”“可以把文本抽成 aspect”“可以清洗 NVD”“可以用通用 truth discovery 估计真值”“模型可以拒判/转交专家”。因此，本项目不能再把以下内容当主要新意：首次发现漏洞数据库差异、首次做字段/aspect 级差异检测、首次使用 LLM 比较漏洞信息、首次允许拒判、首次做冲突消解。

目前仍可能成立、但必须靠新实验兑现的差异是：在已对齐的结构化 NVD–GHSA 字段对上，把差异类型作为**面向维护动作的路由变量**，验证 `EQ/RD/INC/TD/FC/uncertain` 构念是否能被独立真人稳定复现，并证明 type-first routing 相比 binary “所有非相等都升级”在不牺牲 factual-conflict recall 的前提下降低无效审查或改变处理动作。没有 T1/T2，这只是有吸引力的 framing，不是被证据支持的贡献。

## 2. 检索和纳入协议

本轮复用了仓库已有 16 篇全文，再按四条路线补检：最接近的漏洞差异检测；字段/数据库质量与自动 curation；公开数据集与修复证据；选择性预测和 learning-to-defer。优先使用论文 PDF、官方 proceedings、作者 preprint、NIST 页面和公开 artifact。没有取得全文的条目只允许分析标题、元数据和摘要，并明确缺失 baseline、数据、公式与实验细节。

这是一轮面向当前研究决策的 targeted review，不宣称 PRISMA 式系统综述或领域全集。最终投稿前仍需做一次按数据库索引和引用图扩展的检索更新，并核对 2025–2026 preprint 的正式出版状态。

## 3. 路线比较

| 路线 | 代表工作 | 已有能力 | 仍缺能力 | 与本文重叠风险 |
|---|---|---|---|---|
| 文本–结构化版本差异 | VIEM；NVD Chrome reliability | 抽取版本、比较 NVD、人工案例核查 | 结构化两源的 action label 与拒判效用 | 中 |
| 跨源 severity | Croft；CVSS 用户研究；Bayesian CVSS | 测差异、解释人因、估潜在来源质量 | 对单例差异的独立事实 gold 与路由动作 | 中高 |
| 单库质量/修正 | Cleaning NVD；Flaw Within | 多字段质量审计、自动修正候选、downstream sensitivity | 跨源更新机制、两源不可识别与拒判 | 中 |
| aspect/text discrepancy | TOSEM aspect；2025 LLM aspect；VuldiffFinder；GapFinder | 抽取多 aspect、检测 absence/mismatch/语义差异 | 结构化字段的维护动作、source authority | **高** |
| 通用冲突消解 | CRH；truth discovery survey | 来源权重、候选真值、异构距离 | 两源/依赖源可识别、领域证据、abstain | 中；若称 truth discovery 则高 |
| 生态/下游影响 | GHSA review pipeline；VEX tools | 时序机制、工具报告差异 | 字段级因果、真人 action utility | 低到中 |
| 数据与证据基础 | VulZoo；CVEfixes；VFCFinder；data-quality study | 多源聚合、修复 link、代码 lineage、质量审计 | 当前任务上的同合同 gold | 低，但提供强 baseline/resource |
| 拒判/转交 | HSC；Learning to Defer | risk–coverage、系统级转交损失 | 漏洞 curator 的真实动作与专家行为数据 | 概念中等，算法低 |

## 4. 24 篇逐项能力矩阵

| ID | 工作 | 已有能力 | 对本文缺失/不能替代 | 复现资源或证据 | 重叠风险 |
|---|---|---|---|---|---|
| 01 | VIEM | 文本抽软件/版本并与 NVD 比较 | 无结构化两源 taxonomy、裁决和 action study | USENIX PDF、代码 | 中 |
| 02 | Croft severity | 三阶段来源差异与 downstream prediction impact | 单项目、无逐例真值、无字段路由 | PDF、数据/脚本 | 中高 |
| 03 | Flaw Within | NVD 内部“描述近似、分数远离”候选 | 候选不等于错误，无跨源 | 作者 PDF | 中 |
| 04 | Cleaning NVD | 多字段质量审计与修正 | 单库规则不是两源 evidence adjudication | arXiv PDF | 中 |
| 05 | Affected Versions Benchmark | 1,128 漏洞、12 工具的同字段 benchmark | C/C++ 范围；任务是推断版本真值，不是差异类型 | PDF；工具需逐项复现 | 高（affected_versions） |
| 06 | CVSS 用户研究 | 真人/跨时间评分不一致证据 | 不给 NVD–GHSA gold | IEEE S&P PDF | 中 |
| 07 | TOSEM aspect discrepancy | 七 aspect；expression variation vs semantic difference；absence vs mismatch | 已覆盖“差异类型”上位概念，无选源和 action | 全文 PDF | **很高** |
| 08 | LLM aspect discrepancy | LLM 抽取与差异检测 | LLM 不等于 gold；出版元数据还需核 | preprint PDF | 高 |
| 09 | VuldiffFinder | 非结构化漏洞信息差异发现 | 检测不等于裁决/路由 | COSE 全文 | **很高** |
| 10 | GapFinder | 安全文本语义不一致 | 对象偏 CTI，无漏洞字段合同 | 全文 PDF | 低中 |
| 11 | CRH | 联合来源权重与候选真值 | 两源/来源依赖下不可直接识别，无拒判 | 全文 PDF | 中 |
| 12 | Truth Discovery Survey | 方法与假设地图 | 无统一复现，不是漏洞实证 | 全文 PDF | 低 |
| 13 | GHSA Review Pipeline | GHSA 快/慢审核路径与时延 | reviewed 不等于字段正确 | arXiv PDF | 中（TD） |
| 14 | VulZoo | 17 源聚合数据基础 | 聚合不等于冲突解决 | 短 PDF/数据资源 | 低 |
| 15 | VEX Tools | 下游工具报告不一致及来源关联 | 关联非因果，无字段 action A/B | arXiv PDF | 中（动机） |
| 16 | HSC | 不确定时退到粗粒度标签 | 本文五类不是 is-a 层次树 | PDF、代码 | 概念中 |
| 17 | NVD Chrome Reliability | 逐版本核查与下游敏感性 | 旧、单项目，不证明 GHSA 正确 | arXiv PDF | 中（affected） |
| 18 | Bayesian CVSS | 无 gold 下估潜在真值/来源质量；摘要称 NVD 相对最好 | 当前仅摘要级，必须补全文 | closed access metadata | 高（severity baseline） |
| 19 | Automated Curation | 28 VDO 属性、时效与人工节省评价 | 生成属性，不处理两源冲突 | NIST/作者 PDF | 中（效用范式） |
| 20 | Anatomy of VDB | JSS 漏洞数据库系统映射 | 综述不提供方法效果 | CC BY PDF | 低；venue fit 高 |
| 21 | VFCFinder | 排序修复提交并真实回填 GHSA | 补 link 不等于 source truth | PDF、Apache-2.0 代码 | 中（references） |
| 22 | Data Quality for SV Datasets | 五质量维度与模型 sensitivity | 对象是代码数据集，不是 advisory 字段 | PDF、reproduction package | 低中 |
| 23 | Learning to Defer | classifier–expert 系统损失与 rejector | 需要真人决策样本；本文尚无 system utility | PDF、代码 | **高（framing 理论）** |
| 24 | CVEfixes | CVE–VFC–代码 lineage 数据集 | 自动 link/边界不能作无条件 gold | PDF、公开工具/数据 | 中（证据资源） |

## 5. 最接近工作和真正 differential

最接近的不是 CRH，而是三组工作的交叉：TOSEM/VuldiffFinder 已占据“漏洞信息差异检测”；Croft/Automated Curation 已占据“差异或数据选择影响下游任务/人工成本”；Learning to Defer 已占据“按实例决定自动处理还是转交专家”。因此本文的 differential 必须同时满足以下三点：

1. **输入层可审计**：直接比较已对齐的结构化字段 pair，避免文本抽取误差；同时保留字段专用身份/范围/时间合同。
2. **构念层可复现**：五类不是作者自定义的漂亮名字，而是两位真人在盲化材料上能够区分、能保留 `uncertain`，并且相对 binary baseline 有可报告的 reliability/错误结构。
3. **行动层有增量**：类型标签改变实际 action，并相对 `escalate every non-equal pair` 降低无效升级或提升处理针对性；这种收益由独立 action labels 或真实任务记录支持，而不是由 taxonomy 自己循环定义。

只满足第 1 点，贡献更像数据工程；满足 1+2，是一个 taxonomy/measurement paper；三点都满足，才有较可信的 action-oriented JSS framing。

## 6. 同任务 baseline 与资源缺口

必须复现/实现的最低 comparators：

- `binary_raw_difference`：任一原始值不等即升级；这是 type-first 必须打败的主 baseline。
- `binary_canonical_difference`：按当前字段规范化后不等即升级；用于区分 taxonomy 收益和简单 normalization 收益。
- `field_specific_rules_current`：当前 EQ/RD/INC/TD/FC deterministic baseline；用真人 gold 评价，不得把自身输出当标签。
- `always_manual` / `escalate_all_non_equal`：工作量上界与 conflict-recall 参照。
- 若保留裁决主张：`prefer_NVD`、`prefer_GHSA`、`prefer_latest`、`abstain_all`，并在 affected_versions 上考虑已发表工具/修复证据路线；不能只和弱启发式比较。

可复用资源包括 affected-version benchmark、VFCFinder/CVEfixes 的修复链接、VulZoo 多源数据、Croft 与 ICSE data-quality reproduction packages。是否实际接入必须在实验 manifest 中记录；仅引用资源不算 baseline 已复现。

## 7. 阅读顺序

这些论文不是平行清单。先读 07/09，确认“差异检测与类型”已经做到哪里；再读 02/19，理解为什么论文必须证明 downstream/action utility；随后读 23/16，区分 learning-to-defer 与层次退让；再读 11/12/18，理解无 gold、两源依赖与 truth discovery 的可识别性；最后按字段读 05/06/17/21/24，为 severity、affected_versions 和 references 设计真实 comparator 与证据合同。

## 8. 证据边界

本综合只证明文献资产已落盘并完成证据受限阅读，不证明本项目 taxonomy 正确、action routing 有效、human gold 已获得或论文可投稿。CVSS Bayesian 条目仍缺全文；2025–2026 preprint 的最终出版信息也需投稿前刷新。
