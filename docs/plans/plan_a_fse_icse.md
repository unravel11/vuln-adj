# Plan A：FSE 2027 → ICSE 2028 投稿计划

> **历史计划，已停用。** 当前没有按本文件执行 FSE/ICSE 路线；2026-08-23
> 之后的权威路线是 `project_master_plan.md` 和 `paper/jss/` 中的条件式 JSS
> workline。下列内容只作决策追溯，不代表当前 deadline、实验状态或投稿承诺。

**主投**：FSE 2027（CCF-A，截止 2026-10-09）
**备投**：ICSE 2028（CCF-A，截止约 2027-06-30）
**前提**：Plan B（COSE）已投稿

---

## 一、核心判断

Plan A 不是 Plan B 的"加料版"，而是一篇在 Plan B 的检测层基础上，做了一个更难问题的独立论文。

Plan B 的贡献边界：五分类检测 + 基础证据裁决 + 拒判机制，在 NVD↔GHSA 上验证。

Plan A 的新增贡献：
1. 把裁决问题形式化为 precision-constrained coverage maximization（Plan B 里没有这个形式化）
2. 把 affected_versions 的证据解析做成一个独立的硬子任务（Plan B 里没有做深）
3. 用 vulnerable package matching 证明一个硬下游（Plan B 里没有）

这三件事在 Plan B 里明确不做，所以 Plan A 不是增量扩展。

---

## 二、问题定义升级

### Plan B 的问题定义

> 在漏洞记录已通过 CVE-ID 完成对齐之后，对结构化字段值进行差异类型判定，并对 factual_conflict 字段做证据驱动裁决与拒判。

### Plan A 的问题定义

> 在开放世界、证据不完备条件下，对冲突漏洞事实进行选择性裁决（selective adjudication）：在给定误判风险约束下，最大化可安全自动裁决的样本比例。

关键词升级：
- **开放世界**：证据来源不固定，不能假设完备，任何 CVE 的证据集合都可能为空
- **证据不完备**：不是所有冲突都有足够证据支持裁决，这是常态而非异常
- **选择性**：何时该裁决、何时必须 abstain，是核心决策问题，不是后处理
- **误判风险约束**：错误裁决会导致漏报或误报，有安全后果，precision 是硬约束

这样问题就从"数据库维护问题"升级为"高风险安全事实决策问题"。

### 形式化定义

设 $\mathcal{C}$ 为 factual_conflict 字段实例集合，$\mathcal{E}(c)$ 为实例 $c$ 的可用证据集合。

定义裁决函数：

$$\alpha(c, \mathcal{E}(c), \theta) = \begin{cases} v^* & \text{if } \text{Score}(v^*, \mathcal{E}(c)) \geq \theta \\ \perp & \text{otherwise} \end{cases}$$

其中 $v^* = \arg\max_{v \in \{v_{\text{NVD}}, v_{\text{GHSA}}\}} \text{Score}(v, \mathcal{E}(c))$。

定义 coverage 和 precision：

$$\text{Coverage}(\theta) = \frac{|\{c : \alpha(c, \mathcal{E}(c), \theta) \neq \perp\}|}{|\mathcal{C}|}$$

$$\text{Precision}(\theta) = \frac{|\{c : \alpha(c, \mathcal{E}(c), \theta) = v^*_{\text{gold}}\}|}{|\{c : \alpha(c, \mathcal{E}(c), \theta) \neq \perp\}|}$$

**核心优化问题**：

$$\max_{\theta} \text{Coverage}(\theta) \quad \text{s.t.} \quad \text{Precision}(\theta) \geq P_{\min}$$

其中 $P_{\min}$ 是安全语义约束（如 0.90）。

这个形式化的意义：不是"尽量裁决更多"，而是"在保证精度的前提下，尽量裁决更多"。这是一个有安全语义的优化问题，不是启发式打分。

---

## 三、标题

**Selective Adjudication of Conflicting Vulnerability Facts under Incomplete Evidence**

或：

**Field-Level Discrepancy Typing and Selective Adjudication across Aligned Vulnerability Databases**

（第二个标题保留了与 Plan B 的连续性，更适合 ICSE 的实证研究定位）

---

## 四、贡献（四条，与 Plan B 明确区分）

1. **问题形式化**：将漏洞事实冲突裁决形式化为 precision-constrained coverage maximization，给出 risk-coverage 曲线的理论意义（Plan B 没有这个形式化）

2. **affected_versions 证据解析子任务**：提出从 advisory 文本和 patch commit 中解析版本约束的方法，将非结构化证据转化为可与结构化版本范围比较的形式（Plan B 没有做这个）

3. **选择性裁决框架**：在 Plan B 的检测层基础上，实现 precision-constrained 的选择性裁决，报告 risk-coverage 曲线（Plan B 只报单点 accuracy）

4. **下游验证**：在真实软件包版本集合上，量化裁决后 affected_versions 对 vulnerable package matching 的改善（Plan B 没有下游实验）

---

## 五、数据

### 继承自 Plan B

- NVD↔GHSA 8,066 对（主集）
- 差异类型金标（300 实例）
- 裁决金标（150 FC 实例）

### Plan A 新增

| 数据集 | 规模 | 构建方式 | 用途 |
|--------|------|----------|------|
| affected_versions 裁决金标（扩展版） | 200 FC 实例，双标注，kappa ≥ 0.75 | 在 Plan B 的 70 实例基础上扩展 | RQ3 选择性裁决评估 |
| 证据解析子集 | 100 FC 实例，含 advisory 文本 + 解析结果 | 人工标注版本约束解析结果 | RQ2 证据解析评估 |
| 软件包版本集合 | 覆盖裁决 CVE 的真实包版本列表 | 从 PyPI / npm / Maven 等获取 | RQ4 下游评估 |

### 金标质量要求（Plan A 比 Plan B 更严格）

- 双人独立标注
- 冲突仲裁协议（分歧时由第三人裁决）
- 报告 Cohen's kappa（目标 ≥ 0.75）
- 每种差异类型都有足够样本（每类 ≥ 30）

---

## 六、方法框架

Plan A 在 Plan B 的 Layer 1–3 基础上，升级 Layer 3 并新增 Layer 4。

```
Layer 1: 规范化（继承 Plan B）
Layer 2: 差异类型检测（继承 Plan B）
Layer 3: 证据检索与评分（升级）
  3a. 证据检索：references + advisory 链接 + patch commit
  3b. 证据解析（新增）：从 advisory 文本中提取版本约束
  3c. 证据评分：Score(v) = w₁·Authority + w₂·Freshness + w₃·Support + w₄·Agreement
Layer 4: 选择性裁决（新增，Plan B 没有）
  4a. 计算 Score(v₁) 和 Score(v₂)
  4b. 计算 confidence margin = Score(v*) - Score(v_other)
  4c. 在验证集上确定 θ（目标 Precision ≥ P_min）
  4d. 输出裁决值或 abstain
  4e. 报告 risk-coverage 曲线
```

### 证据解析子任务（Plan A 核心新增）

**问题**：给定一个 advisory 页面或 patch commit，从中提取版本约束，转化为可与结构化版本范围比较的形式。

**输入**：advisory 文本（如 "Fixed in version 2.3.1 and later"）或 patch commit message

**输出**：结构化版本约束（如 `{fixed: "2.3.1"}`）

**方法**（不用 LLM，用规则 + 正则）：
- 版本号正则：`\d+\.\d+(\.\d+)*([.-][a-zA-Z0-9]+)*`
- 修复语义词：fixed in / patched in / resolved in / upgrade to / update to
- 受影响语义词：affects / vulnerable in / prior to / before / through
- 输出：`{introduced, fixed, affected_range}` 结构

**评估**：在证据解析子集（100 实例）上报告 extraction precision / recall。

### 选择性裁决的 risk-coverage 曲线

对不同 θ 值，计算：
- Coverage(θ)：可自动裁决的样本比例
- Precision(θ)：裁决正确的比例

绘制 risk-coverage 曲线（x 轴：coverage，y 轴：precision），展示不同 P_min 约束下的最优 θ。

这是 Plan A 的核心图，Plan B 里没有。

---

## 七、研究问题与实验设计

### RQ1：差异分布（继承 Plan B，扩展泛化性）

**问题**：已对齐漏洞数据库中字段级差异的分布与规律是什么？

**数据**：NVD↔GHSA 8,066 对（继承）

**新增**：如果时间允许，加入 NVD↔OSV 来源对，报告两个来源对的差异分布对比。

**输出**：Table 1 + Figure 1（同 Plan B，但可能有第二个来源对的对比列）

---

### RQ2：证据解析准确率（Plan A 新增）

**问题**：从 advisory 文本和 patch commit 中解析版本约束的准确率如何？

**数据**：证据解析子集（100 FC 实例，含 advisory 文本 + 人工标注解析结果）

**基线**：
- B1：正则匹配（无语义词过滤）
- B2：LLM-zero-shot（GPT-4o 直接提取，作为上界参考）

**方法**：规则 + 正则（本文方法）

**指标**：
- Extraction precision（提取的版本约束是否正确）
- Extraction recall（有版本约束的 advisory 中，提取到的比例）
- Downstream impact：解析结果用于裁决后，裁决准确率的变化

---

### RQ3：选择性裁决性能

**问题**：在给定误判风险约束下，选择性裁决能否最大化可安全自动裁决的样本比例？

**数据**：affected_versions 裁决金标（200 FC 实例，双标注）

**基线**：
- B1：Always-NVD
- B2：Always-GHSA
- B3：Recency
- B4：No-abstention scoring（Plan B 的方法，作为直接对比）
- B5：LLM-zero-shot（GPT-4o 直接裁决）

**方法**：选择性裁决（Plan A 方法）

**指标**：
- Selective accuracy（在已裁决样本上的准确率）
- Coverage（裁决样本比例）
- Abstention rate
- Risk-coverage 曲线（核心图）
- AUC of risk-coverage curve（汇总指标）

**消融**：
- 去掉证据解析（只用结构化证据，不解析 advisory 文本）
- 去掉 Authority score
- 去掉 Freshness score
- 去掉 confidence margin（只用 max score，不用 margin）
- 去掉 abstention（= B4）

**预期结论**：
- 选择性裁决在 Precision ≥ 0.90 约束下，coverage 显著高于 Always-NVD/GHSA
- 证据解析子任务对 coverage 有明显贡献（去掉后 coverage 下降）
- LLM-zero-shot 在 precision 上不稳定，risk-coverage 曲线不如本方法

---

### RQ4：下游收益——vulnerable package matching

**问题**：裁决后的 affected_versions 是否改善了 vulnerable package matching 的准确率？

**数据**：
- 取 RQ3 中已裁决的 CVE（预计 100–150 个）
- 对每个 CVE，获取真实软件包的版本列表（从 PyPI / npm / Maven 等）
- 人工标注每个版本是否真正受影响（gold standard）

**方法**：
- 用 NVD 原始版本范围做 matching → precision / recall
- 用 GHSA 原始版本范围做 matching → precision / recall
- 用裁决后版本范围做 matching → precision / recall

**指标**：
- Vulnerable package matching precision / recall / F1
- 裁决前后的 F1 变化（delta F1）

**案例分析**（3–5 个典型 CVE）：
- 展示 NVD 和 GHSA 版本范围冲突如何导致 matching 错误
- 展示裁决后如何修正 matching 结果
- 展示拒判案例：证据不足，保守处理比强制裁决更安全

---

## 八、论文结构

目标页数：12 页（ICSE 双栏格式）

### 1. Introduction（1.5 页）

叙事线：
- 软件供应链安全依赖漏洞数据库，但多源数据库对同一 CVE 的字段值存在冲突
- 核心问题：在证据不完备条件下，如何安全地自动裁决这些冲突？
- 现有工作的不足（同 Plan B，但强调"无形式化、无下游证明"）
- 本文贡献（四条，与 Plan B 明确区分）
- 与 Plan B 的关系：一句话说明本文在 Plan B 的检测层基础上做了什么新的事

### 2. Background and Problem Definition（1 页）

- 漏洞数据库生态（同 Plan B）
- 五类差异定义（引用 Plan B，简要回顾）
- **新增**：selective adjudication 的形式化定义（precision-constrained coverage maximization）

### 3. Method（2.5 页）

- 3.1 规范化与差异检测（引用 Plan B，一段话概述）
- 3.2 证据检索
- 3.3 证据解析子任务（Plan A 新增，重点展开）
- 3.4 证据评分
- 3.5 选择性裁决与 risk-coverage 曲线（Plan A 新增，重点展开）

### 4. Experimental Setup（1 页）

- 数据集（继承 + 新增）
- 金标构建（双标注，kappa 报告）
- 基线与指标

### 5. Results（3 页）

- 5.1 RQ1：差异分布（简要，引用 Plan B 结论）
- 5.2 RQ2：证据解析准确率（Table 2）
- 5.3 RQ3：选择性裁决（Table 3 + Figure 1 risk-coverage 曲线 + 消融 Table 4）
- 5.4 RQ4：下游收益（Table 5 + 案例分析）

### 6. Discussion（0.5 页）

- 为什么选择性裁决比"打分选高者"更重要
- 证据不完备是常态，不是异常
- 对漏洞情报融合工具设计的启示

### 7. Threats to Validity（0.5 页）

### 8. Related Work（1 页）

### 9. Conclusion（0.25 页）

---

## 九、与 Plan B 的关系

| 维度 | Plan B（COSE） | Plan A（ICSE） |
|------|---------------|---------------|
| 问题定义 | 字段级差异检测与裁决 | 选择性裁决（precision-constrained） |
| 技术核心 | 五分类规则 + 证据评分 | 证据解析子任务 + 形式化优化 |
| 裁决评估 | 单点 accuracy + coverage | risk-coverage 曲线 + AUC |
| 下游实验 | 无 | vulnerable package matching |
| 金标质量 | 单人标注，分歧率报告 | 双人标注，kappa ≥ 0.75 |
| 来源对 | NVD↔GHSA | NVD↔GHSA（+ 可选 NVD↔OSV） |

Plan A 在 Related Work 中引用 Plan B，说明本文在 Plan B 的检测层基础上做了什么新的事。ICSE 审稿人不会认为这是增量扩展，因为技术核心（形式化 + 证据解析 + 下游）是 Plan B 里明确没有的。

---

## 十、执行路径

### 前提

Plan B（COSE）已投稿，目标 2026-07 前投出。

### 整体时间线

```
2026-04  Phase D 开始（当前）
2026-07  COSE 投稿
2026-07–09  Plan A 新增工作（金标扩展 + 证据解析 + 选择性裁决）
2026-10  FSE 2027 论文写作 + 投稿（截止 2026-10-09）
2027-01  FSE 通知（预计 2027-01-22）
         → 中：完成
         → 不中：根据审稿意见修改，目标 ICSE 2028
2027-06  ICSE 2028 投稿（截止约 2027-06-30）
```

### FSE 2027 路径（主投）

| 工作项 | 依赖 | 目标完成 |
|--------|------|----------|
| 扩展 affected_versions 裁决金标至 200 实例，引入第二标注者 | Plan B Phase D 完成 | 2026-07 |
| 构建证据解析子集（100 实例，advisory 文本 + 人工标注） | 裁决金标完成 | 2026-08 |
| 实现证据解析模块（规则 + 正则） | 证据解析子集完成 | 2026-08 |
| 实现选择性裁决与 risk-coverage 曲线 | 证据评分模块完成 | 2026-09 |
| 构建软件包版本集合，运行 vulnerable package matching 实验 | 裁决结果完成 | 2026-09 |
| 论文写作 | 所有实验完成 | 2026-10-01 |
| **FSE 2027 投稿** | 论文完成 | **2026-10-09** |

### ICSE 2028 路径（备投，FSE 不中后启动）

FSE 通知时间约 2027-01-22，距 ICSE 2028 截止（约 2027-06-30）有 5 个月。

修改策略取决于审稿意见性质：

| 意见类型 | 修改方向 | 5 个月够用？ |
|----------|----------|-------------|
| 写作和定位问题 | 重写 Introduction / Related Work / Discussion | 够 |
| 实验不够（基线弱、消融不完整） | 补实验，不需要新数据 | 够 |
| 金标规模不足 | 扩展标注，需要时间 | 紧，需要提前准备 |
| 技术核心有根本缺陷 | 重新设计方法 | 不够，需要等 ICSE 2029 |

**关键**：FSE 投稿后，不等通知，立刻开始整理审稿人可能提出的问题并准备应对材料。1 月拿到意见后直接进入修改，不从零开始。

---

## 十一、风险与控制

| 风险 | 概率 | 控制 |
|------|------|------|
| advisory 文本解析规则覆盖率低 | 高 | 只对有明确版本语义词的 advisory 做解析，其余标 abstain；覆盖率低本身是一个发现 |
| 软件包版本集合获取困难 | 中 | 优先选 PyPI 和 npm（版本历史完整），避免 Maven 和 Go |
| FSE 审稿人认为与 Plan B 重复 | 中 | Introduction 第一段明确说明与 Plan B 的关系，强调三个新贡献 |
| 双标注者 kappa 低于 0.75 | 中 | 先做 pilot 标注（30 实例），若 kappa 低则修订 guideline |
| risk-coverage 曲线 AUC 不显著优于基线 | 中 | 实验前先在小样本上验证证据评分的区分度 |
| FSE 不中且审稿意见要求重做实验 | 低 | 5 个月内重做实验风险高；若出现此情况，评估是否等 ICSE 2029 |
