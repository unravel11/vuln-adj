# NVD↔GHSA 字段级差异检测与裁决：实验可行性 + CCF 投稿 + 创新与贡献综合报告

> **历史快照，已停用。** 本文只记录 2026-05-13 当时的材料和判断；后续实验已改变
> 多项前提，当前投稿路线、实验门禁和证据边界以 `project_master_plan.md` 与
> `paper/jss/` 为准。不得用本文的完成度估计或 venue 判断替代当前状态。

**调研时间**：2026-05-13
**项目位置**：`/home/xiaoyuliang/code/vuln-adj`
**资料范围**：项目内 4 份 plan 文档 + 17 篇相关文献 + 2026-05 最新检索（10+ 篇 2025-2026 新增工作）

---

## 一、当前实验进度的诚实盘点

| 模块 | 计划状态 | 实际成熟度 | 关键缺口 |
|------|---------|-----------|---------|
| 数据规范化 + 8066 对齐 | ✅ 完成 | **高** | 无 |
| 五分类检测规则（severity、cwe_ids、published） | ✅ baseline 完成 | **高**（三层决策树清晰） | 无 |
| 五分类检测规则（affected_versions） | ✅ baseline 完成 | **中**（16 条启发式路径，FC 已从 1272→652） | LLM draft 显示仍有 30% baseline false positive，需第二轮规则收紧或扩大金标 |
| 五分类检测规则（references） | ✅ baseline 完成 | **中**（host/URL 双层规范化，但 7763 条 INC 主导，FC 仅 3 条） | references 字段对 RQ2/RQ3 几乎无贡献，应在论文中弱化或合并 |
| Phase D 抽样脚本 | ✅ 完成 | **高**（种子 20260506 可复现） | 无 |
| LLM 辅助 draft 标注 | ✅ 完成 180 条 | **中**（断点续跑+重试齐全，但 abstain 率 65%-83%） | 当前 draft 不能直接当金标，关键样本未抓证据正文 |
| **人工金标填充** | ❌ 未开始 | **零** | 这是 Plan B/A 当前最大单点风险 |
| **证据驱动裁决与拒判脚本** | ❌ 未实现 | **零**（`experiments/rq3_adjudication/` 仅占位 README） | Plan B 核心 RQ3 没有可跑代码 |
| 下游 vulnerable package matching | ❌ 未实现 | **零**（`experiments/rq4_stress_test/` 仅占位 README） | Plan A 的 RQ4 没有任何代码 |
| 第二位标注者 / κ 报告 | ❌ 单人标注 | **零** | Plan A 双标注 + κ ≥ 0.75 的硬指标无法满足 |

**Plan B 完成度估计：约 50%**（数据 + 检测层完成，标注 + 裁决 + 写作未完成）
**Plan A 完成度估计：约 30%**（检测层共享，新增 4 个核心工作项均未开始）

---

## 二、实验方法可行性评估

### 2.1 Plan B（COSE，2026-07 投稿）

**可行性判定：中-高**，前提是 5–7 月集中完成下面 3 件事：

1. **裁决脚本实装**（最关键）：当前 `experiments/rq3_adjudication/` 只有 README，必须实现：
   - 证据检索：从 references 字段提取 advisory/patch URL（已有 URL 规范化，可复用）
   - 证据评分：`Score = w₁·Authority + w₂·Freshness + w₃·Support + w₄·Agreement`
   - 拒判：`max_score ≥ θ` 否则 abstain
   - **风险**：LLM draft 已经显示 80% 样本 abstain，说明大量 FC 缺乏可用证据。`abstain` 率高本身可以写成发现，但要在 Introduction 提前预告，避免审稿人认为方法无效。

2. **人工金标填充**（必须做）：
   - severity 80 条 + affected_versions 100 条已经有 LLM draft，直接在 CSV 上人工复核成本最低
   - **关键修订**：先抓取每条样本的 advisory 正文（vendor、GHSA、NVD 链接），再让人工或 LLM 在有证据的前提下裁决；当前 prompt 已经写明"无正文不裁决"，所以是数据收集问题而非方法问题
   - 单人标注在 COSE 可以接受，但必须报告 20% 复核分歧率（计划里已经写了）

3. **与 VuldiffFinder (COSE 2025) 的 differentiation**（编辑层面的硬门槛）：
   - 同刊上一年已经接收 VuldiffFinder，输入是非结构化文本
   - **本文必须在 Abstract 第二句、Introduction 第一段、Related Work 开头三个位置都明确说"本文输入是已对齐的结构化字段对（NVD↔GHSA），不是描述文本"**
   - 否则有 desk-reject 风险

**Plan B 投稿前不该做的事**（避免延误）：
- 不要补第二位标注者（COSE 允许单人）
- 不要做 vulnerable package matching（留给 Plan A）
- 不要尝试 risk-coverage 曲线（Plan B 单点 accuracy 已足）

### 2.2 Plan A（FSE 2027 主投，2026-10-02 截稿）

**可行性判定：中-高（如时间管理得当）**，关键风险：

1. **截稿时间**：调研结果显示 FSE 2027 全文截稿 **2026-10-02 AoE**（不是计划文档里写的 10-09，需要修正）。距今约 4 个月 20 天。
2. **金标质量**：FSE 审稿人对 κ ≥ 0.75 + 双标注是事实标准。当前单人标注 + 无 κ 是直接致命的 construct validity 弱点。**必须 6 月底前找到第二位标注者**（学生/同事均可）。
3. **下游实验**：FSE 偏好"端到端 impact"，没有 vulnerable package matching 实验很难突破。但实验可以收窄：只对 PyPI/npm 两个生态、150 个已裁决 CVE、3000 个真实包版本做实验，而不是对全部生态做。
4. **18+4 页 vs 内容密度**：可行。Plan A 内容（形式化 + 证据解析 + 选择性裁决 + 下游）在 18 页内可放下，但要砍掉 Plan B 的检测细节，作为"前置工作引用"。

**降级路径（如果 8 月评估时下游未跑通）**：
- 改投 **MSR 2027**（预计 2026-10 截稿，CCF-B，与本工作风格契合度极高）
- 或 **USENIX Security 2027 Cycle 2**（2027-01-26，重写为安全包装版本，强调扫描器误判率）

### 2.3 Plan A 与 Plan B 关键冲突点

**COSE 与 FSE 双投不能直接 self-plagiarism**。Plan A 的 4 个新增贡献（形式化、证据解析、selective adjudication、下游）必须在 FSE 论文中作为主体，且 Related Work 显式引用 Plan B 论文（已知 COSE 发表后才能引用，时间窗口紧）。

**修订建议**：
- COSE 论文标题：`Field-Level Discrepancy Typing across Aligned Vulnerability Databases`（去掉"adjudication"，把裁决作为附加内容）
- FSE 论文标题：`Selective Adjudication of Conflicting Vulnerability Facts under Incomplete Evidence`
- 让两篇标题就能让审稿人看出非重复

---

## 三、CCF venue 推荐表（基于 2026-05 最新调研）

| 优先级 | Venue | CCF | 截稿 | 匹配度 | 关键备注 |
|--------|-------|-----|------|--------|----------|
| ⭐ 主投 P1 | **COSE**（Plan B） | B | 滚动 | 高 | VuldiffFinder 同刊证主题正当，需 differentiation；纯确定性方法契合其 AI 适度政策 |
| ⭐ 主投 P2 | **FSE 2027** | A | **2026-10-02** | 中-高 | 需双标注 + 下游实验；18+4 页可容纳 |
| ⭐ 备投 | **MSR 2027** | B | 预计 2026-10 | 高 | 实证导向最契合；10 页限制；可同时与 FSE 拉开角度（更偏 dataset/mining） |
| 备选 | **EMSE 期刊** | B | 滚动 | 高 | Security Testing 特刊已开；篇幅充足；审稿 9-15 月 |
| 备选 | **USENIX Sec 2027 Cycle 2** | A | 2027-01-26 | 中 | 必须重写威胁模型；FSE 被拒后转投合理 |
| 备选 | **TSE / TOSEM** | A 期刊 | 滚动 | 中-高 | 期刊适合扩展版（300 金标、双源对、双标注） |
| 备选 | **ICSE 2028** | A | 2027-06 预计 | 中-高 | FSE 不中后顺延，10+2 页要砍内容 |
| 不建议 | S&P/CCS/TIFS/NDSS | A | — | 低 | novelty 门槛过高，规则+证据评分容易被认为算法薄 |
| 不建议 | VLDB/SIGMOD | A | — | 低 | 应用域不匹配 |
| 不建议 | ICSE 2027 / ESEM 2026 / ASE 2026 / DSN 2026 | A/B | 已过或太紧 | 低 | 时间窗口已过或不足以补金标 |

**最终建议组合**：
- **2026-07** 投 **COSE**（Plan B）
- **2026-10-02** 投 **FSE 2027**（Plan A）
- 不中则 **2027-01-26 投 USENIX Sec 2027 Cycle 2** 或 **2026-12 投 MSR 2027**

---

## 四、修订后的完整实验方法

### 4.1 整体架构（5 层，比原方案多 1 层）

```
Layer 0：数据收集与对齐                  [Plan B 已完成]
  NVD 2023-2025 (100,032) + GHSA (28,785) → CVE-ID align → 8,066 对

Layer 1：字段规范化                        [Plan B 已完成]
  severity canonical map / version range parser / CWE/date/URL normalization

Layer 2：五分类差异类型检测                [Plan B 已完成 baseline]
  per-field 确定性规则 → {EQ, RD, INC, TD, FC}
  规则源自 Bleiholder & Naumann (2009) 的 schema/identity/value 三分类，
  在漏洞域细化为五类（新增 INC 和 TD 两轴）

Layer 3：证据检索                          [Plan B 待实装]
  3a. 从 references 字段提取候选证据 URL
  3b. 按 host 分类：vendor advisory / GitHub advisory / patch commit / 其他
  3c. （可选）抓取证据正文（Plan A 必须，Plan B 可选）

Layer 4：证据评分（VulScore）              [Plan B 待实装]
  Score(v) = w₁·Authority + w₂·Freshness + w₃·Support + w₄·Agreement
  - Authority：vendor / official-patch / CNA / 其他 四档
  - Freshness：advisory lastModified 与 CVE 发布时间的差
  - Support：候选值字符串出现在证据正文中
  - Agreement：上下文字段（如同 CVE 其他字段）的一致度

Layer 5：裁决与拒判                        [Plan B 待实装，Plan A 升级为选择性裁决]
  Plan B：max(Score(v₁), Score(v₂)) ≥ θ → 输出，否则 abstain
  Plan A：精度约束 max θ Coverage(θ) s.t. Precision(θ) ≥ P_min（=0.90）
        + 报告 risk-coverage 曲线 + AUC

[Plan A 新增 Layer 6：下游 vulnerable package matching]
  对 PyPI/npm 真实包版本，比较裁决前后的 P/R/F1
```

### 4.2 数据集与金标（修订规模）

| 子集 | Plan B | Plan A | 用途 |
|------|--------|--------|------|
| 检测金标 | 300 字段实例，单人 + 20% 复核 | 300（同 B）+ 双标注，κ ≥ 0.75 | RQ2 |
| 裁决金标 | 150（severity 80 + affected_versions 70） | 扩至 200（affected_versions 200，双标注） | RQ3 |
| 证据解析子集 | — | 100 实例，含 advisory 正文 + 解析金标 | RQ2-evidence-parse |
| 下游包版本集合 | — | PyPI + npm 真实版本，覆盖 150 裁决 CVE | RQ4 |

### 4.3 研究问题（Plan B 三问 / Plan A 四问）

**RQ1（共享）**：已对齐漏洞数据库中字段级差异的分布与类型构成是什么？
- 数据：全量 8,066 对
- 输出：5×5 分布表 + 热力图

**RQ2-Plan B**：确定性规则能否准确检测五类差异？
- 数据：300 检测金标
- 基线：Raw exact match / Normalized equality / 三分类启发式
- 指标：accuracy / macro-F1 / per-type F1 / per-field F1
- 消融：去掉规范化 / 去掉 4 条 affected_versions 收紧规则

**RQ2-Plan A**：从 advisory 文本中解析版本约束的准确率？
- 数据：100 证据解析金标
- 基线：纯正则 / LLM-zero-shot (作上界参考)
- 指标：extraction P/R/F1 + 下游裁决 accuracy 变化

**RQ3-Plan B**：证据驱动裁决 + 拒判能否提升融合可信性？
- 数据：150 裁决金标
- 基线：Always-NVD / Always-GHSA / Recency / No-abstention
- 指标：accuracy / coverage / **selective accuracy（核心）** / abstention rate
- 消融：4 项评分各去掉一项 / 去掉 abstention

**RQ3-Plan A**：在 precision ≥ 0.90 约束下，选择性裁决能否最大化 coverage？
- 数据：200 裁决金标
- 基线：B1–B4 同 Plan B + B5 LLM-zero-shot
- 指标：selective accuracy + risk-coverage 曲线 + AUC
- 消融：5 项

**RQ4-Plan A**：裁决后的 affected_versions 是否改善 vulnerable package matching？
- 数据：PyPI/npm 真实包版本，覆盖 150 裁决 CVE
- 方法：NVD-only / GHSA-only / 裁决后，三种 matching 的 P/R/F1
- 案例：3-5 个 CVE 的前后对比

---

## 五、创新点与主要贡献（已根据创新空白验证修订）

### 5.1 必须保持的 contribution（在 2026-05 检索下仍是空白）

✅ **C1（最核心）**：**首个在已对齐的 NVD↔GHSA 结构化字段对上，完成"字段级差异类型化 + 证据驱动裁决 + 拒判"完整闭环的工作。**
- 区别于 VIEM（非结构化文本→结构化字段）、aspect-level / VuldiffFinder（文本→文本）、CRH（通用真值发现无领域语义）
- 区别于 CRVA-TGRAG (arXiv 2604.14172，2026-03)：本文是确定性规则+证据评分，CRVA-TGRAG 是 LLM-RAG

✅ **C4**：**首次将拒判机制系统性引入漏洞数据库字段级裁决。**
- 拒判在恶意软件分类 (AURORA 2025)、入侵检测 2025 已用过，但**漏洞数据库融合场景下未见先例**
- Plan A 进一步升级为 precision-constrained coverage maximization 的形式化

### 5.2 必须弱化措辞的 contribution（避免被认为重新发明）

🔄 **C2**：从原"提出五分类差异类型体系"改为：
> "**将 Bleiholder & Naumann (ACM CSUR 2009) 的经典 schema/identity/value 三分类细化到漏洞数据库语义，新增 temporal_discrepancy 和 incomplete 两类，以刻画漏洞情报特有的时序与完备性问题。**"
- temporal_discrepancy 与 GHSA Pipeline (MSR 2026) 的快/慢路径直接对应，是真正的新轴
- incomplete 区分了"缺失"与"冲突"，避免对无对手值做真值发现

🔄 **C3**：从原"提出 Authority+Freshness+Support+Agreement 评分公式"改为：
> "**面向漏洞字段语义实例化 provenance-aware 证据评分（VulScore）**：4 项指标如何用漏洞域显式信号落地——Authority 用 vendor/official-patch/CNA 三档显式编码、Freshness 用 advisory lastModified 而非通用衰减、Support 用证据正文中字符串匹配、Agreement 用规范化字段相等度。"
- 致敬 CRH (SIGMOD 2014) 与 Bertino & Lim (2008) 的 provenance-based trust 文献
- 命名为 `VulScore` 突出领域专门化

### 5.3 Plan A 独有的 contribution（与 Plan B 不重复）

✅ **C5（Plan A）**：将裁决问题形式化为 **precision-constrained coverage maximization**，给出 risk-coverage 曲线在漏洞融合场景的理论意义。

✅ **C6（Plan A）**：**affected_versions 证据解析子任务**——从 advisory 文本/patch commit 中提取版本约束（fixed/introduced/affected_range）的确定性方法。

✅ **C7（Plan A）**：**下游验证**——在真实 PyPI/npm 包版本集合上量化裁决后 vulnerable package matching 的 F1 改善。

---

## 六、必须新增到 Related Work 的工作（基于 2025-2026 检索）

| # | 论文 | 用途 |
|---|------|------|
| N1 | Conflicting Scores, Confusing Signals (arXiv 2508.13644, 2025) | 强动机引用 |
| N2 | Tug-of-War / CRVA-TGRAG (arXiv 2604.14172, 2026) | 最近邻方法对手，需划界 |
| N3 | Resolving Conflicting Evidence in AFC (IJCAI 2025) | 通用方法论参照 |
| N4 | Ground-Truth Evaluation across Ecosystems (arXiv 2604.21111, 2026) | OSV 互补 |
| N5 | The Baby Steps of EUVD (arXiv 2602.14313, 2026) | 时效背景 |
| N6 | LLMs for Security Advisory Investigations (arXiv 2506.13161, 2025) | 支撑"为何不依赖 LLM 裁决" |
| N7 | LLM-Enabled OSS in GHSA (arXiv 2604.04288, 2026) | 支撑"GHSA 不可单独依赖" |
| N9 | AURORA (selective methods in malware, arXiv 2505.22843, 2025) | 安全域 selective prediction 先例 |
| Bleiholder & Naumann 2009 (ACM CSUR) | **必须引用**避免重新发明 |

时效动机的开篇钩子（Introduction 第一段）：
> 2024 年起 NIST NVD 出现严重积压，2026-04 NIST 宣布转向风险优先模式，只对最高风险 CVE 做完整富化（infosecurity-magazine, 2026-04）；同期 EUVD 上线、GHSA 占据快路径角色（MSR 2026）。这一变化使多源融合从"可选"变为"必要"，但已对齐字段级冲突如何安全自动裁决仍是开放问题。

---

## 七、未来 21 周的关键执行节点（如严格按 Plan B + Plan A 推进）

| 周期 | 工作 | 产物 |
|------|------|------|
| 5 月 15 日前 | 人工填充 180 条 LLM draft（先抓证据正文） | 第一版裁决金标 |
| 5 月 31 日前 | 实装证据检索 + VulScore + 拒判脚本（`experiments/rq3_adjudication/`） | RQ3 可运行 |
| 6 月 15 日前 | 跑通 RQ1 / RQ2 / RQ3 全部图表 | Plan B 实验完整 |
| 6 月 30 日前 | COSE 论文初稿（含 VuldiffFinder differentiation 段） | Plan B 投稿稿 |
| **7 月 31 日** | **COSE 投稿** | — |
| 8 月 - 9 月 | 双标注扩到 200 + 证据解析子集 100 + 下游 PyPI/npm 实验 | Plan A 新增实验 |
| 9 月 30 日前 | Plan A 全部图表 + 论文初稿 | FSE 投稿稿 |
| **10 月 2 日** | **FSE 2027 投稿** | — |

---

## 八、最大的三个被拒风险点（按概率排序）

1. **VuldiffFinder differentiation 不充分**（COSE 概率：高）→ 必须在 Abstract、Introduction、Related Work 三处显式说明输入差异
2. **单人金标 / 无 κ**（FSE 概率：高）→ 6 月底前找第二位标注者
3. **下游 vulnerable package matching 缺失**（FSE 概率：中-高）→ 即使收窄到 PyPI+npm 也必须做，否则 FSE 风险极高

---

## 附录 A：调研引用 URL（全部已通过 WebFetch/WebSearch 实际访问）

### CCF venue
- [FSE 2027 Research Papers](https://conf.researchr.org/track/fse-2027/fse-2027-papers)
- [ICSE 2027 Research Track](https://conf.researchr.org/track/icse-2027/icse-2027-research-track)
- [ICSE 2027 Important Dates](https://conf.researchr.org/dates/icse-2027)
- [SE Deadlines](https://se-deadlines.github.io/)
- [ASE 2026 Research Track](https://conf.researchr.org/track/ase-2026/ase-2026-research-track)
- [USENIX Security 2027](https://www.usenix.org/conference/usenixsecurity27)
- [IEEE S&P 2027 CFP](https://sp2027.ieee-security.org/cfpapers.html)
- [ACM CCS 2026 CFP](https://www.sigsac.org/ccs/CCS2026/call-for/call-for-papers.html)
- [NDSS 2027 CFP](https://www.ndss-symposium.org/ndss2027/submissions/call-for-papers/)
- [MSR 2026](https://2026.msrconf.org/)
- [SANER 2027](https://conf.researchr.org/home/saner-2027)
- [ISSRE 2026 CFP Research](https://cyprusconferences.org/issre2026/cfp-research/)
- [DSN 2026 CFP](https://dsn2026.github.io/cfpapers.html)
- [Computers & Security Guide for Authors](https://www.sciencedirect.com/journal/computers-and-security/publish/guide-for-authors)
- [EMSE Security Testing Special Issue CFP](https://emsejournal.github.io/special_issues/2024_SI_SECUTE.html)

### 相关工作（2025-2026 新增）
- [VuldiffFinder (COSE 2025)](https://www.sciencedirect.com/science/article/abs/pii/S0167404825001361)
- [Conflicting Scores, Confusing Signals (arXiv 2508.13644)](https://arxiv.org/abs/2508.13644)
- [Tug-of-War / CRVA-TGRAG (arXiv 2604.14172)](https://arxiv.org/abs/2604.14172)
- [Resolving Conflicting Evidence in AFC (IJCAI 2025)](https://www.ijcai.org/proceedings/2025/1073)
- [Ground-Truth Evaluation across Ecosystems (arXiv 2604.21111)](https://arxiv.org/abs/2604.21111)
- [EUVD Empirical Inquiry (arXiv 2602.14313)](https://arxiv.org/abs/2602.14313)
- [LLMs for Security Advisory Investigations (arXiv 2506.13161)](https://arxiv.org/abs/2506.13161)
- [LLM-Enabled OSS in GHSA (arXiv 2604.04288)](https://arxiv.org/abs/2604.04288)
- [AURORA Selective Methods in Malware (arXiv 2505.22843)](https://arxiv.org/abs/2505.22843)
- [Uncertainty-Aware Adaptive IDS (MDPI)](https://www.mdpi.com/2313-576X/11/4/120)
- [Characterizing GHSA Review Pipeline (arXiv 2602.06009)](https://arxiv.org/html/2602.06009v1)
- [SZZ for Vulnerability (ICSE 2022)](https://conf.researchr.org/details/icse-2022/icse-2022-papers/76/SZZ-for-Vulnerability-Automatic-Identification-of-Version-Ranges-Affected-by-CVE-Vul)
- [From Industrial Practices to Academia (MSR 2025)](https://2025.msrconf.org/details/msr-2025-technical-papers/11/From-Industrial-Practices-to-Academia-Uncovering-the-Gap-in-Vulnerability-Research-a)
- [Bleiholder & Naumann, Data Fusion (ACM CSUR 2009)](https://dl.acm.org/doi/10.1145/1456650.1456651)
- [Data Fusion in Three Steps (HPI)](https://hpi.de/fileadmin/user_upload/fachgebiete/naumann/publications/DEBull06.pdf)
- [Provenance Based Conflict Handling](https://link.springer.com/content/pdf/10.1007/978-3-642-29023-7_29.pdf)
- [NIST NVD 选择性富化政策 (Infosecurity Magazine, 2026-04)](https://www.infosecurity-magazine.com/news/nvd-enrichment-premarch-2026/)
- [CONFACT 数据集 (IJCAI 2025)](https://github.com/zoeyyes/CONFACT)
