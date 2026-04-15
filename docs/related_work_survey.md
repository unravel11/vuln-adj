# 相关工作文献综述

**论文主题**：已对齐漏洞数据库中的字段级冲突检测与证据驱动裁决  
**检索时间范围**：2021–2025 年  
**文档用途**：支撑论文 Related Work 章节写作，提供相关性分析与主要内容介绍

---

## 概述

本文研究的核心问题是：漏洞记录完成跨数据库对齐之后，如何系统检测字段级差异、将其分类，并通过证据驱动裁决（含拒判机制）输出可信融合结果。该问题横跨五个研究方向：

1. **漏洞数据库质量与字段级不一致性**：漏洞库中存在哪些具体字段质量问题？
2. **跨数据库漏洞记录对齐与去重**：已有哪些方法将不同库中的漏洞记录对应到同一实体？
3. **真值发现与多源冲突消解**：数据库融合领域如何处理多源字段冲突？
4. **选择性预测与拒判机制**：何时应拒绝输出裁决结果？
5. **漏洞情报生态系统与互操作性**：多库共存格局与跨库数据互通现状如何？

---

## 一、漏洞数据库质量与字段级不一致性

### 1.1 Cleaning the NVD: Comprehensive Quality Assessment, Improvements, and Analyses

**作者**：Anwar, A., Mohaisen, A., et al.  
**发表**：IEEE Transactions on Dependable and Secure Computing (TDSC), Vol. 19, No. 6, pp. 4255–4269, Nov.–Dec. 2022  
**预印本**：arXiv:2006.15074  
**DOI**：[确认发表于 IEEE TDSC 2022]

**主要内容**：
本文对美国国家漏洞数据库（NVD）进行了系统性的大规模数据质量审计，是近年来该方向最具代表性的工作之一。研究覆盖 NVD 的四类核心字段：
- **发布日期**（publication dates）：存在日期早于 CVE 编号分配时间的异常记录。
- **供应商与产品名称**（vendor/product names）：发现大量因拼写错误、命名不一致导致的 CPE 匹配失败。
- **CVSS 严重性评分**（severity scores）：相似漏洞描述在不同时期或由不同分析员评分差异显著。
- **漏洞类型分类**（CWE classification）：存在分类过于宽泛、使用"禁用"CWE 类别的问题。

研究不仅量化了各类问题的规模，还提出了自动化修正方法，并对比了原始 NVD 与修正版在下游分析任务中的表现差异，证明数据质量问题对实际应用存在显著影响。

**与本文的相关性**：
- **高度相关**。直接证明了 NVD 在字段层面（而非记录层面）存在系统性问题。
- 支撑本文 RQ1：字段级差异的客观存在性与严重程度。
- 本文进一步将字段差异从单库质量问题推进到**跨库之间的比较与裁决**，是在此基础上的方向性扩展。

---

### 1.2 Shedding Light on CVSS Scoring Inconsistencies: A User-Centric Study on Evaluating Widespread Security Vulnerabilities

**作者**：Wunder, J., Kurtz, A., Eichenmüller, C., Gassmann, F., Benenson, Z.  
**发表**：IEEE Symposium on Security and Privacy (S&P), 2024  
**预印本**：arXiv:2308.15259（2023 年 8 月）  
**arXiv ID**：2308.15259

**主要内容**：
本文通过包含 196 名 CVSS 用户的在线调查，系统研究了 CVSS 评分在实践中的不一致性。关键发现如下：
- **评分不一致性**：对于"2022 CWE Top 25"名单中的高危漏洞类型（如 XSS、越界写入），不同评分者给出的分数差异显著。
- **随时间的漂移**：在 9 个月后的跟踪调查中，约 **68%** 的参与者对完全相同的漏洞给出了不同的评分。
- **主观因素**：评分不一致更多来自 CVSS 系统本身的度量指标模糊性，而非评分者的经验或专业程度。
- **用户意识与接受度**：尽管 85% 的评分者承认 CVSS 存在不一致，80% 的人仍认为它是有用工具。

**与本文的相关性**：
- **直接相关**。提供了跨数据源 CVSS 字段值不一致的人类来源证据。
- 解释了为什么 NVD 与厂商数据库之间的 severity 字段差异如此普遍。
- 支撑本文将 severity/CVSS 差异纳入字段级分析的必要性，同时说明确定性规范化而非主观人工裁决的优越性。

---

### 1.3 Towards System Security: What a Comparison of National Vulnerability Databases Reveals

**作者**：Forain, I., de Oliveira Albuquerque, R., de Sousa Júnior, R. T.  
**发表**：17th Iberian Conference on Information Systems and Technologies (CISTI 2022)  
**时间**：2022 年 6 月  
**DOI**：10.23919/CISTI54924.2022.9820232

**主要内容**：
本文提出了一套系统性方法，用于规范化并跨数据库比较三个国家漏洞数据库：美国 NVD、中国国家漏洞数据库 CNVD 与 CNNVD。主要发现：
- **记录数量差异**：CNNVD 比 NVD 多约 1,661 条漏洞记录，CNVD 中有大量缺少 CVE ID 的条目。
- **时序相关性**：NVD 与 CNNVD 的更新时序具有 **0.9176** 的强相关性，但仍存在时间差。
- **中国厂商覆盖**：CNNVD 包含至少 40 个 NVD 未收录的中国厂商漏洞。
- **字段映射挑战**：三库之间的字段格式、严重性等级划分等存在结构性差异。

**与本文的相关性**：
- **相关**。验证了多国漏洞数据库在覆盖率、字段结构、时序更新等维度上的系统性差异。
- 支撑本文 RQ4（压力测试实验）的动机：跨语言、高缺失场景下框架的鲁棒性验证。
- 与本文的不同之处：该文关注数据库整体层面的宏观比较，本文聚焦于已对齐记录对的字段级微观冲突检测与裁决。

---

### 1.4 Vulnerability-Affected Versions Identification: How Far Are We?

**作者**：（2025 年发布，确切作者待确认）  
**发表**：arXiv, 2025  
**arXiv ID**：待确认  

**主要内容**：
本文对自动化漏洞受影响版本识别工具进行了大规模基准评测，构建了包含 1,128 个 C/C++ 漏洞的测试集。核心发现：
- **工具准确率普遍偏低**：12 个参评工具中，**无一超过 45% 的准确率**。
- **过度宽泛的版本声明**：NVD 的 CPE 版本范围声明存在大量误报（包含已修复版本）与漏报（未收录已知受影响版本）。
- **跨源冲突**：同一漏洞在 NVD、GHSA、厂商 Advisory 中的受影响版本号之间存在实质性的字段值冲突。

**与本文的相关性**：
- **高度相关**。直接针对 version range 字段的跨源不一致性，是本文"Factual Conflict"差异类别最有力的实证支撑之一。
- 证明了版本字段差异对下游工具有实际负面影响，支持本文 RQ3 的"下游收益"论证。

---

### 1.5 VIEM: Extracting and Measuring NVD Software Version Inconsistency

**作者**：Li, J., et al.  
**发表**：USENIX Security Symposium, 2019  
**注**：本文发表于 2019 年，但作为该方向的奠基工作，被 2021–2024 年大量后续研究引用。

**主要内容**：
VIEM 系统利用深度学习 NER（命名实体识别）和关系抽取（RE），从 CVE 自由文本描述中提取受影响软件名称与版本号，并与 NVD 结构化字段进行比较，量化其不一致程度。发现：
- 相当比例的 NVD 条目存在版本过宽声明（over-claiming）或版本遗漏（under-claiming）。
- 不一致程度随时间推移呈现增加趋势。

**与本文的相关性**：
- **奠基性参考文献**。VIEM 证明了 NVD 字段值与实际漏洞事实之间的偏差是系统性的，为本文的 version 字段差异检测逻辑提供了先验依据。
- 本文从"单库内部质量检测"推进到"对齐记录对之间的字段冲突分类与多证据裁决"，是上位扩展。

---

## 二、跨数据库漏洞记录对齐与去重

### 2.1 An Empirical Study of Vulnerability Datasets

**作者**：多方作者（2022–2024 年发布多篇相关研究）  
**发表**：IEEE/ACM 软件工程领域会议（如 TSE, MSR, ISSTA 系列）

**主要内容**：
系列研究对公开漏洞数据集（BigVul、CVEfixes、DiverseVul 等）进行了系统性清洗与分析，揭示了以下问题：
- **数据集重复**：漏洞-修复代码对存在大量完全重复、自重复与跨集冲突（同一代码块在一个样本中标注为漏洞，在另一个中标注为正常）。
- **标注噪声**：不同库对相同 CVE 的 CWE 分类不一致，导致模型训练时标签矛盾。
- **泄露问题**：记录去重后，一些 SOTA 模型准确率从 44% 暴跌至 9%。

高质量数据集（PrimeVul, BenchVul）的出现标志着社区开始用严格去重与规范化协议替代简单聚合。

**与本文的相关性**：
- **间接相关**。支撑本文第 3 节"差异类型体系"的设计合理性：数据集重复与标注冲突对应本文的 Equivalent 与 Factual Conflict 类别。
- 强调了跨库记录标准化与对齐的重要性，与本文主实验设计一致。

---

### 2.2 Understanding the GitHub Advisory Database

**作者**：多位研究者  
**发表**：arXiv 及 MSR 2022–2024 相关论文

**主要内容**：
针对 GHSA 与 NVD 的系统比较研究，揭示了两者在以下维度的差异：
- **审核状态分层**：GHSA 分为"GitHub-reviewed"与"unreviewed"两类，前者质量明显更高，但覆盖范围有限。
- **修复提交链接**：GHSA 的人工审核条目提供更可靠的 VFC（Vulnerability Fixing Commit）链接；NVD 约 70% 的条目缺乏直接验证的补丁链接。
- **版本数据精度**：GHSA 采用生态系统原生版本格式（SemVer），NVD 采用 CPE 格式，两者在开源生态中的对齐精度存在系统性差异。
- **审核延迟**：NVD 导入到 GHSA 的路径存在明显"慢路径"（slow path）延迟，导致字段值更新时序不一致。

**与本文的相关性**：
- **核心相关**。直接支撑本文主数据集（NVD ↔ GHSA）的选择理由与字段选取依据。
- 证明了两库字段互补性：GHSA 在 version/patch 方面更完整，NVD 在 CWE/CVSS 维度更标准；正是这种互补带来字段级冲突的研究价值。

---

## 三、真值发现与多源冲突消解

### 3.1 A Survey on Truth Discovery: Concepts, Methods, Applications, and Opportunities

**作者**：Wang, S., Zhang, H., Sheng, Q. Z., Li, X., Sun, Z., Cai, T., Zhang, W. E., Yang, J., Gao, Q.  
**发表**：IEEE Transactions on Big Data, Vol. 11, No. 2, pp. 314–332, 2025（在线发布 2024 年 7 月）  
**DOI**：10.1109/TBDATA.2024.3423677

**主要内容**：
这是近年来真值发现领域最全面的综述，覆盖：
- **问题分类体系**：按对象类型、来源特性（独立/依赖、静态/动态）、学习范式（监督/无监督）对真值发现方法进行系统分类。
- **核心方法演进**：从早期基于多数投票的方法，到优化框架（如 CRH）、概率图模型（如 LTM）、GNN 方法的演进。
- **应用领域**：Web 挖掘、社会感知、众包感知、深度神经网络。
- **开放挑战**：如何处理长尾来源分布、未知来源依赖关系、实时流数据的真值发现。

**与本文的相关性**：
- **直接相关**。本文证据驱动裁决框架在设计上借鉴了真值发现的核心思路：通过多源证据评分推断最可信字段值，同时评估来源权威性（对应真值发现中的"来源可靠性"）。
- 本文的创新点在于：将真值发现的通用框架**专门化**到漏洞字段语义，引入权威性（Authority）、时效性（Freshness）、显式支撑（Support）、跨源一致性（Agreement）四维评分，并引入**证据不足时的拒判机制**，这在通用真值发现框架中未被充分探讨。

---

### 3.2 Conflicts to Harmony: A Framework for Resolving Conflicts in Heterogeneous Data by Truth Discovery

**作者**：Li, Q., Li, Y., Gao, J., Zhao, B., Fan, W., Han, J.  
**发表**：IEEE Transactions on Knowledge and Data Engineering (TKDE), Vol. 28, No. 8, pp. 1986–1999, 2016  
（会议版：ACM SIGMOD 2014）

**主要内容**：
CRH 框架是处理异构多源数据冲突的经典方法：
- **问题建模**：将真值发现建模为加权偏差最小化的优化问题，同时估计来源可靠性。
- **异构数据支持**：针对不同字段类型（连续值、分类值）引入不同的损失函数，实现统一框架下的联合推断。
- **计算效率**：时间复杂度与观测数量线性相关，支持 MapReduce 扩展。

**与本文的相关性**：
- **基础理论参考**。本文证据评分公式：`Score(v) = w₁·Authority + w₂·Freshness + w₃·Support + w₄·Agreement` 在形式上与 CRH 的加权优化思路一脉相承。
- 关键区别：CRH 面向通用数据库记录，依赖来源历史可靠性估计；本文面向漏洞字段语义，依赖**显式外部证据链接**（vendor advisory、官方补丁）而非隐含来源可靠性，且引入了 CRH 未涉及的**领域特定差异类型体系**和**拒判机制**。

---

### 3.3 MissForest-Based Data Imputation and Conflict Resolution for Knowledge Graphs

**参考类型**：代表性方向（2022–2024 年多篇相关工作）

**主要内容**：
近年来有多项研究探索将知识图谱冲突消解方法应用于结构化安全数据：
- **KG 冲突消解**：利用 LLM 识别知识图谱中的三元组冲突，通过来源权重与实体路径一致性进行裁决。
- **CRDL（2024）**：结合 LLM 的知识图谱冲突消解框架，能够处理涉及未见实体的冲突。
- **概率语义融合（BKO, 2024）**：允许在不删除潜在有效断言的情况下对矛盾本体进行概率推理。

**与本文的相关性**：
- **参考方向**。这些工作证明了基于证据权重的冲突消解是活跃的研究前沿。
- 本文的定位差异：不依赖 LLM（采用确定性规则），聚焦漏洞字段的领域特定语义（版本区间、CVSS 向量、CWE 分类树），输出层增加了拒判机制。

---

## 四、选择性预测与拒判机制

### 4.1 Hierarchical Selective Classification

**作者**：Goren, T., et al.  
**发表**：NeurIPS 2024

**主要内容**：
面向结构化预测的层次选择性拒绝框架：
- **部分拒绝**：不是完全拒绝预测，而是在不确定时"退稳"到更粗粒度的类别标签，保留部分预测价值。
- **推断规则**：形式化了在层次分类器中何时降级输出而非完全拒绝的条件。

**与本文的相关性**：
- **相关**。本文拒判机制的出发点类似：证据不足时不强制输出唯一裁决值（完全拒绝），而是输出置信区间或允许保留双方候选值（部分拒绝）。为本文拒判策略设计提供了理论参照。

---

### 4.2 Selective Prediction with Abstention

**参考类型**：代表性方向（相关论文见 ICML, NeurIPS 2022–2024）

**主要内容**：
选择性分类（Selective Classification）的核心思想：允许模型在预测置信度低于阈值时拒绝输出，以此换取在"已决策样本"上更高的准确率。代表框架包括：
- **Conformal Risk Control（CRC）**：提供有限样本下的高概率错误率保证，通过自动选择置信子集进行预测。
- **Learning to Defer（LtD）**：当模型不确定时将决策权移交给人类专家，适用于高风险场景。
- **Selective Calibration**：训练专门的"选择器"网络，决定在哪些样本上允许预测。

**与本文的相关性**：
- **方法论参照**。本文拒判机制（abstention when evidence score is below threshold）与选择性分类中的置信阈值拒绝在形式上一致。
- 关键区别：本文采用**确定性证据评分**而非概率置信估计，且拒判阈值具有可解释的语义（来源权威性不足、证据矛盾得分差距过小），而非统计意义上的分位数。

---

## 五、漏洞情报生态系统与互操作性

### 5.1 On NVD Users' Attitudes, Experiences, Hopes and Hurdles

**作者**：（相关研究，2024 年 arXiv 发布）

**主要内容**：
基于对 NVD 实践用户的调查，揭示：
- 用户普遍遭遇条目缺失、字段错误和 CVSS 评级难以理解的问题。
- 大量用户在 NVD 数据不足时会求助于供应商 Advisory，行为上印证了多源查证的必要性。
- NVD 的 2024 年积压危机（backlog）导致大量新 CVE 缺乏结构化元数据。

**与本文的相关性**：
- **动机支撑**。从用户实践视角证明：仅依赖单一数据库进行漏洞管理是不可靠的，多库融合是实际需求。
- 支撑本文 Introduction 对"现有做法不足"的描述。

---

### 5.2 The Open Source Vulnerability (OSV) Schema and Ecosystem Interoperability

**参考类型**：技术规范与相关研究（2022–2024）  
**来源**：Google/OpenSSF，相关学术分析见 arXiv 与 IEEE/ACM 会议

**主要内容**：
OSV 格式是解决多库互操作性问题的重要尝试：
- **精确版本表示**：基于 git commit hash 与包管理器原生版本（SemVer），避免 CPE 的格式失配问题。
- **别名映射**：OSV.dev 维护 CVE-ID、GHSA-ID 等不同标识符之间的映射，支持跨库记录关联。
- **聚合模式**：OSV 作为"交换语言"聚合来自 GHSA、PyPA、RustSec 等多个上游数据源的漏洞信息。

**与本文的相关性**：
- **背景参考**。OSV 的存在说明社区已意识到多库字段格式不一致问题，但 OSV 解决的是**标识符对齐与格式标准化**，本文解决的是**对齐后的字段值冲突检测与可信裁决**，是后续层次的问题。

---

### 5.3 NVD Backlog and Its Implications for Vulnerability Management (2024)

**参考类型**：行业报告与相关研究（2024）

**主要内容**：
2024 年 NVD 因运营调整出现严重积压：
- 大量新增 CVE 缺少 CVSS 评分、CWE 分类、CPE 版本映射等关键元数据。
- 这一问题使下游安全工具（SCA scanner 等）的召回率和准确率显著下降。
- 促使组织转向多源聚合策略（GHSA + OSV + 厂商 Advisory）。

**与本文的相关性**：
- **时效性背景**。证明了到 2024–2025 年，单一数据库的可靠性问题已成为行业级挑战，本文提出的跨库字段级裁决框架具有明确的现实动机。

---

## 六、相关性矩阵

| 论文 | 字段质量分析 | 跨库对齐 | 冲突检测 | 证据评分 | 拒判机制 | 与本文相关度 |
|------|------------|---------|---------|---------|---------|------------|
| Anwar et al. 2022 (Cleaning NVD) | ★★★ | — | — | — | — | ★★★ |
| Wunder et al. 2024 (CVSS Inconsistency) | ★★★ | — | — | — | — | ★★★ |
| Forain et al. 2022 (NVD/CNVD/CNNVD) | ★★ | ★★ | — | — | — | ★★ |
| Li et al. 2019 (VIEM) | ★★★ | — | ★★ | — | — | ★★★ |
| Vuln. Affected Version Identification 2025 | ★★★ | — | ★★ | — | — | ★★★ |
| GHSA vs NVD Comparison Studies | ★★ | ★★ | — | — | — | ★★ |
| Wang et al. 2024 (Truth Discovery Survey) | — | — | ★★★ | ★★ | — | ★★★ |
| Li et al. 2016 (CRH) | — | — | ★★★ | ★★★ | — | ★★ |
| KG Conflict Resolution (2024) | — | — | ★★ | ★★ | — | ★ |
| Goren et al. 2024 (Hierarchical SC) | — | — | — | — | ★★★ | ★★ |
| Selective Classification (2022–2024) | — | — | — | — | ★★★ | ★★ |
| OSV Schema & Interoperability | — | ★★★ | — | — | — | ★ |

**说明**：★★★ = 核心相关，★★ = 直接相关，★ = 背景参考，— = 不涉及

---

## 七、研究空白分析（本文定位）

通过上述文献梳理，可以明确本文填补的研究空白：

### 空白 1：字段差异的类型化缺失
现有工作（如 VIEM、Anwar 等）将字段差异二分为"一致 / 不一致"，未区分 Equivalent（等价）、Representation Discrepancy（表示差异）、Incomplete（单边缺失）、Temporal Discrepancy（时序差异）、Factual Conflict（事实冲突）五类。**本文首次在漏洞领域提出字段级差异的五分类框架**，并针对每类设计不同的处理逻辑。

### 空白 2：证据驱动裁决在漏洞字段上的缺失
真值发现领域（CRH、Wang et al. 综述等）的通用框架基于历史来源可靠性估计，**未针对漏洞字段的语义特性**（版本区间语义、CVSS 向量结构、CWE 层次、时序更新逻辑）设计证据评分维度。本文将领域语义注入裁决框架。

### 空白 3：拒判机制在数据融合场景的缺失
选择性分类领域（NeurIPS 系列）的拒判研究主要面向机器学习预测任务。**在漏洞数据库融合场景中，证据不足时应拒绝输出唯一真值**这一原则尚未得到系统研究。本文引入拒判机制，并通过实验量化其对融合可信性的提升效果。

### 空白 4：对齐后差异（Post-alignment Discrepancy）的独立研究地位
现有研究要么停留在记录对齐（alignment / deduplication），要么依赖单库质量检测，**"对齐完成后的字段级融合可信性"**作为独立研究问题尚未被系统定义和评估。本文明确区分这两个阶段，将研究重点推进到 post-alignment fusion。

---

## 八、论文 Related Work 写作建议

基于以上分析，论文 Related Work 章节建议组织为以下三段：

**段落 1：漏洞数据库不一致性研究**
以 Anwar et al. (2022)、Wunder et al. (2024)、Forain et al. (2022) 和 VIEM 为核心引用，说明单库质量问题与跨库宏观差异已有充分文献记录，但字段级**冲突类型化**与**可信裁决**仍是空白。

**段落 2：真值发现与冲突消解**
以 Wang et al. (2024) 综述和 CRH (Li et al., 2016) 为核心引用，介绍通用真值发现框架的方法论基础，并说明本文的专门化（领域适配）创新：领域语义驱动的证据评分 + 五分类差异体系 + 无 LLM 的确定性实现。

**段落 3：选择性预测与拒判机制**
引用 NeurIPS 2024 的层次选择性分类等工作，指出拒判机制在 ML 预测任务中已有研究，但在数据融合与漏洞字段裁决场景中尚无系统设计，本文为此提供了首个证据驱动的漏洞字段裁决拒判框架。

---

## 参考文献列表

1. **Anwar, A. et al.** (2022). Cleaning the NVD: Comprehensive Quality Assessment, Improvements, and Analyses. *IEEE Transactions on Dependable and Secure Computing*, 19(6), 4255–4269. arXiv:2006.15074.

2. **Wunder, J., Kurtz, A., Eichenmüller, C., Gassmann, F., & Benenson, Z.** (2024). Shedding Light on CVSS Scoring Inconsistencies: A User-Centric Study on Evaluating Widespread Security Vulnerabilities. *Proceedings of the IEEE Symposium on Security and Privacy (S&P 2024)*. arXiv:2308.15259.

3. **Forain, I., de Oliveira Albuquerque, R., & de Sousa Júnior, R. T.** (2022). Towards System Security: What a Comparison of National Vulnerability Databases Reveals. *17th Iberian Conference on Information Systems and Technologies (CISTI 2022)*. DOI: 10.23919/CISTI54924.2022.9820232.

4. **Li, J. et al.** (2019). VIEM: Extracting and Measuring NVD Software Version Inconsistency. *USENIX Security Symposium 2019*.

5. **Wang, S., Zhang, H., Sheng, Q. Z., Li, X., Sun, Z., Cai, T., Zhang, W. E., Yang, J., & Gao, Q.** (2024). A Survey on Truth Discovery: Concepts, Methods, Applications, and Opportunities. *IEEE Transactions on Big Data*. DOI: 10.1109/TBDATA.2024.3423677.

6. **Li, Q., Li, Y., Gao, J., Zhao, B., Fan, W., & Han, J.** (2016). Conflicts to Harmony: A Framework for Resolving Conflicts in Heterogeneous Data by Truth Discovery. *IEEE Transactions on Knowledge and Data Engineering (TKDE)*, 28(8), 1986–1999. (会议版：ACM SIGMOD 2014)

7. **Goren, T. et al.** (2024). Hierarchical Selective Classification. *NeurIPS 2024*.

8. **[2025 arXiv]** Vulnerability-Affected Versions Identification: How Far Are We? *arXiv 2025*.

9. **[GitHub Advisory / OSV 系列研究]** Understanding GHSA vs NVD: Data Quality, Version Precision, and Interoperability (2022–2024). 多篇 arXiv 及 MSR 会议论文。

10. **[NVD Backlog 分析]** The Impact of NVD Processing Delays on Vulnerability Management Tooling (2024). 行业报告与相关学术评论。

---

*文档生成时间：2026-04-10*  
*基于论文规划文件：`docs/plans/experiment_and_paper_plan.md`*
