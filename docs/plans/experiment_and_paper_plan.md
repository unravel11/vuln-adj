# 字段级冲突检测与证据驱动裁决论文：实验与写作规划

## 1. 论文定位

### 1.1 题目方向
**Detecting and Adjudicating Field-Level Discrepancies across Aligned Vulnerability Databases**

中文可表述为：
**已对齐漏洞数据库中的字段级冲突检测与证据驱动裁决**

### 1.2 核心问题
本文不研究“两个漏洞记录是否对应同一漏洞”，而研究：

> 在漏洞记录已经完成对齐之后，不同数据库在字段层面为何仍然不一致，这些差异应如何被自动检测、分类、并在外部证据支持下完成可信裁决。

### 1.3 论文主线
整篇论文围绕三条原则展开：

1. **差异必须先类型化，再处理**；不能把所有字段差异都视为统一冲突。
2. **裁决必须受证据约束**；不能直接依赖单一数据库字段值。
3. **可信融合必须允许拒判**；证据不足时不应强制输出唯一真值。

---

## 2. 研究问题（RQ）

### RQ1
**What types of field-level discrepancies exist across aligned vulnerability databases, and how are they distributed across fields and sources?**

已对齐漏洞数据库之间存在哪些字段级差异？这些差异在不同字段和不同来源对之间如何分布？

### RQ2
**How accurately can field-level discrepancies be detected and typed using deterministic normalization and field-specific comparison rules?**

利用确定性规范化和字段特定比较规则，能否准确检测并分类字段级差异？

### RQ3
**Can evidence-driven adjudication with abstention improve the trustworthiness of post-alignment vulnerability data fusion?**

带拒判机制的证据驱动裁决，能否提升对齐后漏洞数据融合的可信性？

### RQ4（可选）
**How robust is the framework under high-missingness and cross-lingual settings?**

在高缺失、跨语言、弱结构场景下，该框架是否仍然成立？

---

## 3. 数据集规划

## 3.1 主数据集：NVD ↔ GHSA

### 目标
作为主实验集，用于完成：
- 字段级差异分布统计
- 差异类型检测评估
- 裁决前后的对比实验

### 选择理由
NVD 与 GHSA 相比 CNVD/CNNVD 更适合作为主数据源，因为：
- NVD 具有较完整的 CVSS、CWE、references 等结构化字段
- GHSA 往往提供明确的 affected ranges、patched/unaffected 信息以及丰富引用
- 两者字段互补性强，适合做“冲突检测 + 裁决”闭环

### 对齐方式
优先采用相同 CVE-ID 作为锚点，构建共享漏洞记录对。

### 建议字段
主实验优先保留以下字段：
1. affected version / version range
2. severity / CVSS
3. CWE / vulnerability type
4. publish / update date
5. references
6. affected product / package（若结构足够稳定）

patch / fix status 可优先用于裁决子集，不必在主大集全量强制覆盖。

---

## 3.2 裁决金标子集：Vendor Advisory 子集

### 目标
从主数据集共享漏洞中抽取带有厂商官方通告、发布说明、补丁提交或官方修复说明的记录，构建高可信裁决样本集。

### 用途
用于评估：
- adjudication accuracy
- abstention quality
- evidence sufficiency

### 建议规模
- 100–300 个冲突字段实例
- 优先覆盖 version、severity、date、references / fix fields

### 标注内容
对每个样本标注：
- adjudicated value
- supporting evidence URL
- evidence snippet
- whether abstention is appropriate

---

## 3.3 补充压力测试集：NVD ↔ CNVD / CNNVD

### 目标
作为补充实验，而不是主实验数据集。

### 用途
用于回答：
- 在高缺失、跨语言、弱结构场景下，框架是否仍能稳定工作？
- 方法是否会自然将大量样本识别为 Incomplete？
- 哪些字段在该场景下仍然可比？

### 注意事项
该部分不适合承担“全字段裁决”的主结论，更适合作为 stress test 或附录扩展实验。

---

## 4. 差异类型体系

对每个字段输出以下五类之一：

1. **Equivalent**：值不同但语义一致
2. **Representation Discrepancy**：表述不同，不构成事实冲突
3. **Incomplete**：一方缺失，另一方存在
4. **Temporal Discrepancy**：由于更新时间不同造成阶段性差异
5. **Factual Conflict**：双方字段值在事实层面不兼容

### 说明
这五类不是表面命名，而是后续决策逻辑的核心：
- Equivalent / Representation → 规范化或合并
- Incomplete → 补全，不做“选边”
- Temporal → 进入时间敏感裁决
- Factual Conflict → 进入证据驱动裁决

---

## 5. 方法框架

## 5.1 整体流程

1. 输入已对齐漏洞记录对
2. 映射到统一 schema
3. 对字段进行规范化
4. 执行字段级差异类型判定
5. 对 Temporal / Factual 冲突执行证据检索与评分
6. 进行裁决或拒判
7. 输出裁决值、证据、置信度与拒判标记

---

## 5.2 统一表示与规范化层

### 目标
将异构漏洞记录映射到统一、可比较的字段表示。

### 技术实现
- vendor / product canonicalization
- version range parsing and normalization
- CVSS / severity mapping
- CWE normalization
- date normalization
- URL / host parsing for references

### 推荐方式
优先采用确定性规则、解析器和映射表，不使用 LLM。

---

## 5.3 字段级差异检测层

### version / version range
采用：
- exact equality
- normalized equality
- interval overlap
- subset relation
- disjointness

### severity / CVSS
采用：
- numeric comparison
- severity-level mapping
- vector consistency（若有）

### CWE / vulnerability type
采用：
- canonical ID match
- parent-child taxonomy relation
- weakness text normalization

### dates
采用：
- chronological consistency
- update-gap reasoning

### references
采用：
- host overlap
- official-source presence
- URL set comparison

---

## 5.4 证据检索与评分层

### 适用对象
仅对 Temporal Discrepancy 和 Factual Conflict 字段执行。

### 证据来源
- vendor advisory
- official patch / commit
- release notes
- official reference links
- 官方漏洞说明页面

### 证据评分维度
设候选字段值为 v，其评分为：

`Score(v) = w1 * Authority(v) + w2 * Freshness(v) + w3 * Support(v) + w4 * Agreement(v)`

其中：
- Authority：来源权威性
- Freshness：信息时效性
- Support：显式文本/链接支撑
- Agreement：跨源支持程度

### 决策规则
- 若最高分显著高于次高分，则输出该值
- 若最高分不足阈值，或前两者差距过小，则 abstain
- 若双方仅为表示差异，则输出统一规范化值

---

## 5.5 最终输出

对每个字段输出：
- discrepancy type
- adjudicated value
- winning source
- supporting evidence
- confidence level
- abstain / unresolved

---

## 6. 标注与金标集构建

## 6.1 差异类型金标集

### 目标
用于评估 discrepancy detection / typing。

### 建议规模
- 300–800 个字段实例

### 标注方式
- 两名标注者独立标注
- 分歧样本仲裁
- 报告 Cohen's kappa

### 标注对象
每个字段实例标一个标签：
- Equivalent
- Representation Discrepancy
- Incomplete
- Temporal Discrepancy
- Factual Conflict

---

## 6.2 裁决金标子集

### 目标
用于评估 adjudication correctness。

### 建议规模
- 100–300 个冲突字段实例

### 标注内容
- 最终正确值
- 支撑证据来源
- 是否应拒判

### 标注要求
只对具备明确外部证据的样本给出裁决真值；证据不足则允许标为 abstain / unresolved。

---

## 7. 实验设计

## 7.1 实验一：差异分布与类型构成（RQ1）

### 目的
统计主数据集中不同字段上的差异分布与类型占比。

### 输入
全量 NVD ↔ GHSA 对齐记录对。

### 输出指标
- field availability
- discrepancy rate
- per-type distribution
- factual conflict ratio per field

### 预期结论
- version 与 severity 是高冲突字段
- dates 更容易表现为 temporal discrepancy
- 大量“不同”并非 factual conflict

---

## 7.2 实验二：差异检测性能（RQ2）

### 目的
评估确定性规范化与字段规则的差异检测能力。

### 数据
差异类型金标集。

### 基线
1. raw exact match
2. normalized equality only
3. simple field heuristics

### 方法
full deterministic discrepancy typing

### 指标
- overall accuracy
- macro-F1
- per-type F1
- per-field F1

### 预期结论
- 规范化显著优于原始精确匹配
- 五分类比 same/different 更能解释真实差异

---

## 7.3 实验三：裁决性能与拒判收益（RQ3）

### 目的
评估证据驱动裁决是否优于静态来源优先，并量化拒判收益。

### 数据
裁决金标子集。

### 基线
1. source-priority heuristic
2. freshest-source heuristic
3. no-abstention evidence scoring

### 方法
full evidence scoring + abstention

### 指标
- adjudication accuracy
- coverage
- abstention precision
- selective accuracy
- risk-coverage tradeoff（可选）

### 预期结论
- 证据评分优于固定来源优先
- 不拒判会在低证据样本上带来明显错误
- abstention 能提升整体可信性

---

## 7.4 实验四：下游收益（RQ3 扩展）

### 目的
证明这不是单纯数据审计，而是对融合质量有实际帮助。

### 方案 A（推荐）
比较裁决前后 unified field view 的质量：
- unresolved conflict rate
- agreement with official evidence

### 方案 B（可选）
将裁决后的字段表示用于下游 retrieval / matching / candidate filtering，观察性能变化。

### 预期结论
裁决后可显著降低未解决冲突，并提升与官方证据一致性。

---

## 7.5 实验五：补充压力测试（RQ4，可选）

### 数据
NVD ↔ CNVD / CNNVD

### 目的
检验高缺失、跨语言场景下的稳定性。

### 指标
- discrepancy distribution under missingness
- per-field typing performance on comparable fields
- abstention / incomplete rate

### 预期结论
- 框架在高缺失场景下仍然成立
- 输出会更偏向 Incomplete 和 Abstain
- 可比字段应主动收缩

---

## 8. 消融实验建议

建议至少做以下消融：

1. 去掉 normalization，观察差异检测性能变化
2. 去掉 authority score，观察裁决准确率变化
3. 去掉 freshness score，观察 temporal 冲突的表现变化
4. 去掉 abstention，观察错误率变化
5. 仅做 same/different 二分类，与五分类框架比较

---

## 9. 论文结构规划

## 9.1 标准章节结构

### 1. Introduction
- 问题背景
- 为什么“对齐后仍不一致”是独立问题
- 现有工作不足：多字段少、裁决弱、缺拒判
- 论文贡献

### 2. Background and Problem Definition
- 漏洞数据库生态
- post-alignment discrepancy task 定义
- 字段与差异类型定义

### 3. Method
- unified schema and normalization
- discrepancy typing
- evidence retrieval and scoring
- adjudication with abstention

### 4. Experimental Setup
- 数据集
- 标注协议
- 字段与预处理
- 基线与指标

### 5. Results
- RQ1：差异分布
- RQ2：检测性能
- RQ3：裁决与拒判
- RQ4：压力测试（可选）

### 6. Discussion
- 为什么差异不等于冲突
- 为什么拒判是必要的
- 对漏洞情报融合的启示

### 7. Threats to Validity
- 内部效度
- 外部效度
- 构念效度
- 复现性

### 8. Related Work
- 漏洞信息不一致研究
- duplicate detection / alignment
- truth discovery / conflict resolution

### 9. Conclusion
- 总结任务价值、方法、主要发现与未来工作

---

## 10. 预期贡献写法

### Contribution 1
提出已对齐漏洞数据库中的字段级差异检测与裁决任务，将研究重点从 record alignment 推进到 post-alignment fusion。

### Contribution 2
提出一套字段级差异类型体系，区分等价、表示差异、单边缺失、时序差异和事实冲突。

### Contribution 3
提出一种无 LLM 的、确定性的证据驱动裁决框架，并引入拒判机制以保证融合可信性。

### Contribution 4
构建字段级金标与裁决子集，系统评估检测、裁决以及下游收益。

---

## 11. 8 周推进建议

### 第 1–2 周
- 收集并整理 NVD ↔ GHSA 对齐数据
- 定 unified schema
- 收敛字段范围
- 制定差异类型标注规范

### 第 3 周
- 构建差异类型金标试标集
- 实现 normalization 与 typing 规则初版

### 第 4 周
- 完成差异检测实验主结果
- 修订规则与标注边界

### 第 5 周
- 构建 vendor advisory 裁决子集
- 实现 evidence scoring 与 abstention

### 第 6 周
- 完成裁决实验、消融实验与错误分析
- 组织图表和主要发现

### 第 7 周
- 写完整论文初稿
- 补实验细节、附录与 threats to validity

### 第 8 周
- 自审与迭代修改
- 补充必要分析
- 完成投稿版润色

---

## 12. 风险与控制

### 风险 1
GHSA 字段结构不如预期一致。

**控制**：主动收缩到 version / severity / date / references 四字段主实验。

### 风险 2
裁决真值难建立。

**控制**：只对具备官方证据的冲突样本建立裁决金标，不追求全量唯一真值。

### 风险 3
规则覆盖不足。

**控制**：通过 abstention 处理低证据样本，避免为追求覆盖牺牲可信性。

---

## 13. 最终建议

这篇论文最重要的不是“模块多”，而是要把它稳定写成：

> 差异类型化 → 证据约束裁决 → 拒判

只要这三层写稳，整篇论文就会更像方法学，而不是工程拼装。
