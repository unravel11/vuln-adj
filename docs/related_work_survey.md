# 相关工作文献综述

**论文主题**：已对齐漏洞数据库中的字段级冲突检测与证据驱动裁决
**最后更新**：2026-04-22
**文档用途**：支撑论文 Related Work 章节写作；每条目明确标注输入类型、任务类型、与本文的边界区分

---

## 核心定位说明

本文的任务定义：

- **输入**：已通过 CVE-ID 对齐的结构化漏洞记录对（NVD ↔ GHSA）
- **任务**：对结构化字段值进行差异类型判定（五分类），并对 factual_conflict 字段做证据驱动裁决 + 拒判
- **不做**：record alignment、文本抽取、非结构化文本处理

与现有工作的根本区别：现有工作要么处理非结构化文本（NLP 任务），要么只做检测不做裁决，要么是通用真值发现框架（无漏洞领域语义）。本文当前最稳的创新边界是：在已对齐结构化漏洞记录对上做字段级差异类型化，并为 residual factual_conflict 设计证据约束、允许拒判的 source-support 裁决框架。当前 COSE 草稿仍是 baseline / silver-label prototype；在 RQ2/RQ3 human-gold 完成前，不能写成“完整闭环”或最终真值发现系统。

---

## 一、漏洞数据库字段不一致性研究（动机来源）

这一方向的工作证明了字段不一致是真实问题，是本文的动机基础。但这些工作都停在"检测/量化"层面，没有做裁决，也没有区分差异类型。

---

### 1.1 VIEM: Extracting and Measuring NVD Software Version Inconsistency

**作者**：Dong, Y., Chen, B., et al.
**发表**：USENIX Security Symposium, 2019
**arXiv / 代码**：https://github.com/yingdongucas/inconsistency_detection

**输入类型**：非结构化文本（CVE 自由文本描述 + 漏洞报告文本）
**任务类型**：文本抽取（NER + RE）→ 与 NVD 结构化字段比对 → 不一致检测
**不做**：不做裁决，不区分差异类型，不输出可信值

**主要内容**：
从 78,296 个 CVE 和 70,569 份漏洞报告中，用深度学习 NER 和关系抽取从文本中提取软件名和版本号，与 NVD 结构化字段比对。发现仅 59.82% 的报告与 NVD 完全一致，且不一致率随时间增长。

**与本文的边界**：
VIEM 的输入是非结构化文本，任务是 NLP 抽取 + 文本-结构化字段比对。本文的输入是已对齐的结构化字段对，任务是字段值层面的差异类型判定 + 裁决。两者在输入、任务定义和方法上完全不同。VIEM 证明了不一致问题的规模，是本文的动机引用，不是直接竞争对手。

---

### 1.2 An Investigation into Inconsistency of Software Vulnerability Severity across Data Sources

**作者**：Croft, R., Babar, M. A., Li, L.
**发表**：IEEE SANER 2022
**代码**：https://github.com/RolandCroft/An-investigation-into-inconsistency-of-software-vulnerability-severity-data

**输入类型**：结构化 severity 标签（Bugzilla、Mozilla Security Advisory、NVD 三个来源）
**任务类型**：跨源 severity 不一致检测 + 下游预测性能影响分析
**不做**：不做裁决，不区分差异类型，不输出可信值；仅针对 Mozilla Firefox 单一项目

**主要内容**：
分析 Mozilla Firefox 漏洞在三个来源中的 severity 标签不一致，发现 severity 在漏洞生命周期早期常被低估，且这种不一致会使下游 severity 预测性能下降最高 77%。

**与本文的边界**：
Croft 等证明了 severity 不一致对下游任务有实质影响，是本文 severity 字段裁决价值的直接动机。但该工作只做检测和影响分析，不做裁决，且只覆盖单一项目（Mozilla Firefox）。本文在 8066 个 NVD↔GHSA 对上做系统性裁决，覆盖范围和任务定义都不同。

---

### 1.3 The Flaw Within: Identifying CVSS Score Discrepancies in the NVD

**作者**：Zhang, S., Cai, M., Zhang, M., Zhao, L., de Carné de Carnavalet, X.
**发表**：IEEE CloudCom 2023
**链接**：https://people.scs.carleton.ca/~lianyingzhao/Inconsistency_NVD-authorscopy.pdf

**输入类型**：NVD 内部 CVE 描述文本 + CVSS 分数（单库内部）
**任务类型**：单库内部不一致检测（文本聚类找相似描述但分数不同的条目）
**不做**：不跨库，不做裁决，不区分差异类型

**主要内容**：
在 NVD 内部，用文本聚类识别描述相似但 CVSS 分数不同的条目，发现约 4.4% 的 CVE 条目存在内部不一致，说明即使在单一权威数据库内部，评分也不稳定。

**与本文的边界**：
该工作是单库内部质量审计，不是跨库字段比较。它证明了 CVSS 评分本身的主观性和不稳定性，支撑本文"不能直接信任单一来源的 severity 值"这一前提。

---

### 1.4 Cleaning the NVD: Comprehensive Quality Assessment, Improvements, and Analyses

**作者**：Anwar, A., Mohaisen, A., et al.
**发表**：IEEE Transactions on Dependable and Secure Computing (TDSC), Vol. 19, No. 6, 2022
**预印本**：arXiv:2006.15074

**输入类型**：NVD 结构化字段（单库内部）
**任务类型**：单库质量审计 + 自动化修正
**不做**：不跨库，不做裁决

**主要内容**：
对 NVD 的发布日期、vendor/product 名称、CVSS 分数、CWE 分类四类字段进行系统性质量审计，量化各类问题规模，提出自动化修正方法，并对比修正前后在下游分析任务中的表现差异。

**与本文的边界**：
单库质量审计，不是跨库字段级比较。证明了 NVD 字段层面存在系统性问题，支撑本文"不能把 NVD 当作无条件真值来源"的前提。

---

### 1.5 Vulnerability-Affected Versions Identification: How Far Are We?

**作者**：（2025 年发布）
**发表**：arXiv:2509.03876, 2025
**链接**：https://arxiv.org/html/2509.03876v1

**输入类型**：修复提交 + 官方 advisory（结构化 + 半结构化）
**任务类型**：工具评测（12 个自动化工具在识别受影响版本范围上的准确率基准测试）
**不做**：不做跨库字段比较，不做裁决

**主要内容**：
构建包含 1128 个 C/C++ 漏洞的基准测试集（Cohen's Kappa = 0.83），评测 12 个工具。核心发现：无一工具超过 45% 准确率，集成方法最高约 60%，说明受影响版本识别存在根本性局限。

**与本文的边界**：
该工作是工具评测，不是字段级差异检测或裁决方法。但它的核心发现（现有工具在 version 字段上准确率极低）是本文 affected_versions 字段裁决价值的强动机：如果工具本身不可靠，那么跨库字段冲突的裁决就更有必要。

---

### 1.6 Shedding Light on CVSS Scoring Inconsistencies: A User-Centric Study

**作者**：Wunder, J., Kurtz, A., Eichenmüller, C., Gassmann, F., Benenson, Z.
**发表**：IEEE S&P 2024
**预印本**：arXiv:2308.15259

**输入类型**：用户调查数据（196 名 CVSS 评分者）
**任务类型**：用户研究，量化 CVSS 评分的主观性和不一致性
**不做**：不做跨库字段比较，不做裁决

**主要内容**：
对 CWE Top 25 高危漏洞类型，不同评分者给出的分数差异显著；9 个月后跟踪调查发现 68% 的参与者对相同漏洞给出了不同评分；不一致主要来自 CVSS 指标本身的模糊性，而非评分者经验差异。

**与本文的边界**：
从人类评分者角度证明了 severity 不一致的根本来源是评估标准模糊性，支撑本文"不能依赖单一来源 severity 值"的前提，也解释了为什么 NVD 和 GHSA 之间的 severity 差异如此普遍。

---

## 二、Aspect-level 差异检测（最近的竞争对手，但输入不同）

这一方向的工作与本文题目最接近，但输入类型根本不同：它们处理的是非结构化文本，本文处理的是结构化字段对。这个区分必须在 Related Work 里明确说明。

---

### 2.1 Aspect-level Information Discrepancies across Heterogeneous Vulnerability Reports: Severity, Types and Detection Methods

**作者**：（2023 年发布）
**发表**：ACM Transactions on Software Engineering and Methodology (TOSEM), 2023
**DOI**：10.1145/3624734

**输入类型**：非结构化文本（漏洞报告文本、vendor advisory 文本、安全博客文本）
**任务类型**：NLP aspect 抽取 → 跨源文本层面差异检测
**不做**：不处理结构化数据库字段对，不做裁决，不输出可信值

**主要内容**：
从异构漏洞报告的文本描述中抽取 severity、漏洞类型、检测方法等 aspect，检测跨源 aspect 级别的不一致。

**与本文的边界**：
这是目前与本文题目最接近的工作，但输入层完全不同。该工作的输入是非结构化文本，任务是 NLP 抽取 + 文本层面差异检测。本文的输入是已对齐的结构化数据库字段对（NVD ↔ GHSA 的 severity label、version range、CWE ID 等），任务是字段值层面的差异类型判定 + 证据驱动裁决。两者在输入、方法和任务目标上都不同。

---

### 2.2 Vulnerability Aspects Extraction and Discrepancies Detection across Heterogeneous Threat Intelligence

**作者**：Wang et al.
**发表**：ACM, 2025
**DOI**：10.1145/3709018.3736330
**预印本**：https://www.authorea.com/users/860959/articles/1243609

**输入类型**：非结构化威胁情报文本
**任务类型**：NLP aspect 抽取 + 跨源差异检测
**不做**：不处理结构化字段对，不做裁决

**主要内容**：
从异构威胁情报文本中抽取漏洞 aspect，检测跨源差异。

**与本文的边界**：同 2.1，输入是文本，不是结构化字段对。

---

### 2.3 VuldiffFinder: Discovering Inconsistencies in Unstructured Vulnerability Information

**作者**：（2025 年发布）
**发表**：Computers & Security, 2025
**DOI**：10.1016/j.cose.2025.104447
**ScienceDirect**：https://www.sciencedirect.com/science/article/abs/pii/S0167404825001361

**输入类型**：非结构化文本（CVE 描述文本、advisory 文本）
**任务类型**：文本层面不一致发现
**不做**：不处理结构化字段对，不做裁决，不区分差异类型

**与本文的边界**：
该工作发表在与本文相同的目标期刊（Computers & Security）。输入是非结构化文本，本文输入是结构化字段对。需要在 Related Work 里专门说明这一区分，避免审稿人认为本文与 VuldiffFinder 重复。

---

### 2.4 GapFinder: Finding Inconsistency of Security Information From Unstructured Text

**作者**：Jo, H., Kim, J., Porras, P., Yegneswaran, V., Shin, S.
**发表**：IEEE Transactions on Information Forensics and Security (TIFS), 2021
**IEEE**：https://ieeexplore.ieee.org/document/9121316

**输入类型**：非结构化威胁情报文本（面向恶意软件情报，不是漏洞数据库）
**任务类型**：语义不一致检测
**不做**：不处理结构化字段对，不做裁决，不针对漏洞数据库

**与本文的边界**：
面向恶意软件威胁情报，不是漏洞数据库。输入是文本。与本文的关联仅在于"安全领域的不一致检测"这一宽泛主题。

---

## 三、真值发现与多源冲突消解（方法论基础）

这一方向提供了裁决框架的方法论基础，但都是通用框架，没有漏洞领域语义，也没有拒判机制。

---

### 3.1 Conflicts to Harmony: A Framework for Resolving Conflicts in Heterogeneous Data by Truth Discovery (CRH)

**作者**：Li, Q., Li, Y., Gao, J., Zhao, B., Fan, W., Han, J.
**发表**：ACM SIGMOD 2014 / IEEE TKDE, Vol. 28, No. 8, 2016
**DOI**：10.1109/TKDE.2016.2559481

**输入类型**：通用多源结构化数据
**任务类型**：加权偏差最小化，同时估计来源可靠性和候选值真实性
**不做**：无漏洞领域语义，无拒判机制

**主要内容**：
将真值发现建模为加权偏差最小化的优化问题，针对不同字段类型（连续值、分类值）引入不同损失函数，时间复杂度与观测数量线性相关。

**与本文的边界**：
本文证据评分公式 `Score(v) = w₁·Authority + w₂·Freshness + w₃·Support + w₄·Agreement` 在形式上借鉴了 CRH 的加权优化思路。关键区别：CRH 依赖来源历史可靠性估计（隐含），本文依赖显式外部证据链接（vendor advisory、官方补丁）；CRH 无漏洞字段语义，本文有；CRH 无拒判，本文有。

---

### 3.2 A Survey on Truth Discovery: Concepts, Methods, Applications, and Opportunities

**作者**：Wang, S., Zhang, H., Sheng, Q. Z., et al.
**发表**：IEEE Transactions on Big Data, 2024
**DOI**：10.1109/TBDATA.2024.3423677

**主要内容**：
覆盖真值发现领域的问题分类、方法演进（多数投票 → EM → 概率图模型 → GNN）、应用领域和开放挑战的综述。

**与本文的边界**：
方法论参考，不是漏洞领域工作。本文在 Related Work 里引用此综述作为真值发现方法论的背景，说明本文的裁决框架是真值发现思路在漏洞字段语义上的专门化。

---

## 四、漏洞情报生态系统与数据基础（背景与动机）

---

### 4.1 Characterizing and Modeling the GitHub Security Advisories Review Pipeline

**作者**：Segal, C., et al.
**发表**：MSR 2026
**arXiv**：2602.06009

**输入类型**：GHSA 元数据（结构化）
**任务类型**：实证研究，分析 GHSA 审核流程和延迟
**不做**：不做字段级差异检测，不做裁决

**主要内容**：
分析 288,000+ 条 GHSA advisory（2019–2025），识别快路径（GitHub Repository Advisory，GRA）和慢路径（NVD 导入）两种审核模式，建立排队模型。快路径延迟低，慢路径延迟高且不稳定。

**与本文的边界**：
解释了为什么 NVD 和 GHSA 之间会存在时序差异（temporal_discrepancy）：NVD 导入到 GHSA 的慢路径会导致字段值更新时序不一致。这是本文 temporal_discrepancy 类别的直接背景支撑。

---

### 4.2 VulZoo: A Comprehensive Vulnerability Intelligence Dataset

**作者**：（2024 年发布）
**发表**：arXiv:2406.16347

**主要内容**：
聚合 17 个漏洞情报源，构建包含 604,943 条 CVE 记录的统一数据集，明确不做冲突解决，把差异分析留给后续研究。

**与本文的边界**：
数据集论文，不是方法论文。VulZoo 明确指出多源冲突解决是开放问题，支撑本文的研究动机。

---

### 4.3 Vexed by VEX Tools: Consistency Evaluation of Container Vulnerability Scanners

**作者**：（2025 年发布）
**发表**：arXiv:2503.14388

**输入类型**：容器镜像（结构化依赖列表）
**任务类型**：工具一致性评测（7 个 VEX 工具，48 个容器镜像）
**不做**：不做字段级差异分类，不做裁决

**主要内容**：
7 个工具之间最高 pairwise 相似度仅 69.4%，5 个工具共同认可的漏洞只有 3.4%。漏洞数据库差异是工具不一致的最强影响因素（相关系数 0.88）。

**与本文的边界**：
从工具层面证明了跨源漏洞数据不一致对实际安全工具有直接影响，支撑本文的实践动机。

---

### 4.4 NVD Backlog and Selective Enrichment (2024–2026)

**来源**：NIST 官方公告 + 行业报告（Flashpoint, HelpNetSecurity, 2026-04）

**主要内容**：
2024 年起 NVD 出现严重积压，大量新 CVE 缺少 CVSS、CWE、CPE 等关键元数据。2026 年 4 月 NIST 宣布转向风险优先模式，只对最高风险 CVE 做完整富化。这一变化使多源融合从"可选"变为"必要"。

**与本文的边界**：
时效性背景，证明单一数据库可靠性问题已成为行业级挑战，本文提出的跨库字段级裁决框架具有明确的现实动机。

---

## 五、选择性预测与拒判机制（拒判设计的理论参照）

---

### 5.1 Hierarchical Selective Classification

**作者**：Goren, T., et al.
**发表**：NeurIPS 2024

**主要内容**：
面向结构化预测的层次选择性拒绝框架：不确定时"退稳"到更粗粒度的类别标签，而非完全拒绝。

**与本文的边界**：
本文拒判机制的出发点类似：证据不足时不强制输出唯一裁决值。关键区别：本文采用确定性证据评分（来源权威性、时效性、显式支撑），而非统计置信度；拒判阈值具有可解释的安全语义，而非统计分位数。

---

## 六、研究空白定位（本文贡献的精确定位）

基于以上边界分析，本文填补的空白：

**空白 1（最核心）**：没有工作在已对齐的结构化漏洞记录对上做证据驱动裁决。
- 现有检测工作（VIEM、Croft、The Flaw Within、aspect-level 系列）：只检测，不裁决
- 现有真值发现工作（CRH 等）：通用框架，无漏洞领域语义，无拒判
- 现有文本处理工作（VuldiffFinder、GapFinder 等）：输入是非结构化文本，不是结构化字段对

**空白 2**：没有工作区分"需要裁决的差异"和"不需要裁决的差异"。
- 现有工作把所有"不同"都当作问题，没有区分 representation_discrepancy（规范化可解决）、incomplete（补全而非选边）、temporal_discrepancy（时序原因）和 factual_conflict（真正需要裁决）

**空白 3**：没有工作在漏洞数据融合场景中引入拒判机制。
- 现有系统要么强制选一个来源，要么取最大值，没有"证据不足时拒绝输出"的设计

---

## 七、待确认条目

以下条目在本次检索中未能找到具体来源，使用前需核实：

- "2025 年公开的 duplicate vulnerability records across databases 数据集"：检索未找到此具体数据集，如有来源请补充 DOI 或 URL，否则不应写入论文
- Aspect-level Discrepancies (TOSEM 2023) 的完整作者列表：ACM 页面 403，待补充

---

## 参考文献列表

1. Dong, Y., et al. Towards the Detection of Inconsistencies in Public Security Vulnerability Reports. USENIX Security 2019.
2. Croft, R., Babar, M. A., Li, L. An Investigation into Inconsistency of Software Vulnerability Severity across Data Sources. SANER 2022.
3. Zhang, S., et al. The Flaw Within: Identifying CVSS Score Discrepancies in the NVD. CloudCom 2023.
4. Anwar, A., et al. Cleaning the NVD: Comprehensive Quality Assessment, Improvements, and Analyses. IEEE TDSC, 2022. arXiv:2006.15074.
5. Wunder, J., et al. Shedding Light on CVSS Scoring Inconsistencies: A User-Centric Study. IEEE S&P 2024. arXiv:2308.15259.
6. [Authors TBC]. Vulnerability-Affected Versions Identification: How Far Are We? arXiv:2509.03876, 2025.
7. [Authors TBC]. Aspect-level Information Discrepancies across Heterogeneous Vulnerability Reports. ACM TOSEM 2023. DOI:10.1145/3624734.
8. Wang et al. Vulnerability Aspects Extraction and Discrepancies Detection across Heterogeneous Threat Intelligence. ACM 2025. DOI:10.1145/3709018.3736330.
9. [Authors TBC]. VuldiffFinder: Discovering Inconsistencies in Unstructured Vulnerability Information. Computers & Security 2025. DOI:10.1016/j.cose.2025.104447.
10. Jo, H., et al. GapFinder: Finding Inconsistency of Security Information From Unstructured Text. IEEE TIFS 2021.
11. Li, Q., et al. Conflicts to Harmony: A Framework for Resolving Conflicts in Heterogeneous Data by Truth Discovery. ACM SIGMOD 2014 / IEEE TKDE 2016.
12. Wang, S., et al. A Survey on Truth Discovery. IEEE Transactions on Big Data 2024. DOI:10.1109/TBDATA.2024.3423677.
13. Segal, C., et al. Characterizing and Modeling the GitHub Security Advisories Review Pipeline. MSR 2026. arXiv:2602.06009.
14. [Authors TBC]. VulZoo: A Comprehensive Vulnerability Intelligence Dataset. arXiv:2406.16347, 2024.
15. [Authors TBC]. Vexed by VEX Tools: Consistency Evaluation of Container Vulnerability Scanners. arXiv:2503.14388, 2025.
16. Goren, T., et al. Hierarchical Selective Classification. NeurIPS 2024.
