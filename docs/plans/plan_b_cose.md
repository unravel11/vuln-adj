# Plan B：COSE 投稿计划

> **历史计划，已停用。** COSE 稿件和复现包保留为历史证据线，不是当前投稿稿；
> 当前路线、必需实验和 `NO_GO_FOR_SUBMISSION` 状态以 `project_master_plan.md`
> 与 `paper/jss/` 为准。下列阶段状态不得覆盖较新的证据账本。

**目标期刊**：Computers & Security（CCF-B，Elsevier）
**投稿目标**：2026 Q3
**当前状态**：Phase A/B/C 已完成，Phase D/E/F 进行中；human-gold 尚未签收

---

## 一、论文定位

### 问题

漏洞数据库（NVD、GHSA）通过 CVE-ID 对齐后，字段层面仍然存在大量不一致。现有工作要么只检测不裁决，要么处理非结构化文本而非结构化字段对，要么是通用真值发现框架（无漏洞领域语义）。

本文的任务定义：

> 在漏洞记录已通过 CVE-ID 完成对齐之后，对结构化字段值进行差异类型判定（五分类），并对 factual_conflict 字段做证据驱动裁决与拒判。

三条核心原则：
1. 差异必须先类型化，再处理——不能把所有字段差异都视为统一冲突
2. 裁决必须受证据约束——不能直接依赖单一数据库字段值
3. 可信融合必须允许拒判——证据不足时不应强制输出唯一真值

### 标题

**Field-Level Discrepancy Typing across Aligned Vulnerability Databases**

### 贡献（四条）

1. 提出 post-alignment field-level discrepancy 任务，将研究重点从 record alignment 推进到 post-alignment fusion
2. 提出五分类差异类型体系（EQ / RD / INC / TD / FC），区分等价、表示差异、单边缺失、时序差异和事实冲突
3. 设计证据约束的 source-support 裁决框架，引入 both / neither / abstain，避免强制唯一真值输出
4. 构建字段级金标与裁决子集后，系统评估检测、裁决与拒判性能；当前草稿在 gold 完成前只能写作 baseline / silver-label prototype

---

## 二、数据

### 主数据集

- NVD 2023–2025：100,032 条规范化记录
- GHSA snapshot：28,785 条规范化记录
- CVE-ID 对齐结果：**8,066 对**

### 当前 baseline 统计（2026-07-15 input-integrity refresh）

| 字段 | equivalent | repr_discrepancy | incomplete | temporal_discrepancy | factual_conflict |
|------|-----------|-----------------|------------|---------------------|-----------------|
| severity | 3,106 | 3,178 | 33 | — | 1,749 |
| published | — | 6,169 | — | 1,897 | — |
| cwe_ids | 6,813 | 23 | 1,146 | — | 84 |
| references | — | 300 | 7,763 | — | 3 |
| affected_versions | 425 | 3,936 | 3,054 | — | 651 |

注：affected_versions.factual_conflict 曾由规则修订从 1,272 收紧至 652；2026-07-15 过滤 NVD `vulnerable=false` CPE 后进一步变为 651。本表仍是 deterministic baseline 输出，不是人工金标。

### 金标建设计划

| 子集 | 规模 | 标注要求 | 用途 |
|------|------|----------|------|
| 差异类型金标 | 300 字段实例，全字段分层抽样 | 单人标注，记录边界案例 | RQ2 检测评估 |
| 裁决金标 | 180 FC 实例（severity 80 + affected_versions 100），含证据链接 | 人工标注与独立复核，证据不足标 abstain | RQ3 裁决评估 |

RQ2 primary 中抽取 20% 样本做独立二次核查并报告一致性；RQ3 final 行必须记录独立 reviewer 签收。AI candidate 只能作为预标注，不能替代 human-gold。

---

## 三、方法框架

### 整体流程

```
输入：已对齐记录对 (r_NVD, r_GHSA)
  ↓
Layer 1: 规范化
  severity canonical map（MODERATE→MEDIUM 等）
  version range parser（end_including/excluding 语义统一）
  CWE ID 规范化
  date 格式统一
  URL dedup + host normalization
  ↓
Layer 2: 字段级差异类型判定（五分类）
  per-field 确定性规则 → {EQ, RD, INC, TD, FC}
  ↓
Layer 3: 证据驱动裁决（仅对 FC 激活）
  证据检索：references 字段 + NVD/GHSA advisory 链接
  证据评分：Score(v) = w₁·Authority + w₂·Freshness + w₃·Support + w₄·Agreement
  裁决决策：max_score ≥ θ → 输出裁决值；否则 → abstain
  ↓
输出：(discrepancy_type, adjudicated_value, evidence, confidence, abstain_flag)
```

### 五分类差异类型定义

| 类型 | 触发条件 | 处理方式 |
|------|----------|----------|
| Equivalent (EQ) | 规范化后语义一致 | 合并，取任一 |
| Representation Discrepancy (RD) | 表述不同但事实一致（如 end_including vs end_excluding 同边界） | 规范化后合并 |
| Incomplete (INC) | 一方缺失，另一方存在 | 补全，不选边 |
| Temporal Discrepancy (TD) | 差异可由更新时间差解释 | 取最新值，标注时间戳 |
| Factual Conflict (FC) | 以上均不满足，双方事实不兼容 | 进入裁决层 |

### 字段特定规则（关键规则列举）

**severity**
- CVSS label 规范化映射（MODERATE→MEDIUM，CRITICAL→CRITICAL 等）
- 规范化后相同 → EQ
- 规范化后不同 → FC（severity 无 INC / TD 主路径）

**affected_versions**
- 精确匹配 → EQ
- effective_affected_span 等价（end_including vs end_excluding 同边界）→ RD
- 一方为另一方子集 → INC
- 共享 upper-bound endpoint → RD
- end_including vs end_excluding 且共享 major.minor 前缀 → RD
- NVD 点版本落在 GHSA 可解析范围内 → RD
- end_excluding 字符串前缀截断 → RD
- NVD 使用日期字符串作为 version_end_excluding → RD
- 以上均不满足 → FC

**published**
- 格式差异（T00:00:00 vs 无时间戳）→ RD
- 日期不同 → TD（发布时间差异归因于数据库更新时序）

### 证据评分

> 当前状态边界：以下评分公式、权重网格搜索和阈值选择是计划中的最终方法设计，尚未实现或在 human-gold 上验证。当前已运行的 RQ3 方法是字段特定的 evidence/token/package baseline，必须按 baseline 报告。

```
Score(v) = w₁·Authority(source) + w₂·Freshness(evidence_date)
         + w₃·Support(explicit_mention) + w₄·Agreement(cross_source)
```

- Authority：vendor.com / github.com/advisories > github.com/commit > 其他
- Freshness：证据发布时间与 CVE 发布时间的差值（越近越高）
- Support：证据文档中是否出现与候选值匹配的字符串（0/1）
- Agreement：两个来源中有多少其他字段一致（上下文一致性）

计划在独立验证集上通过网格搜索确定权重 w₁–w₄，并报告各权重的消融结果；当前尚未执行。

### 拒判机制

```
if max(Score(v₁), Score(v₂)) ≥ θ:
    output argmax
else:
    output abstain
```

计划在裁决金标验证集上选取 θ，目标为 precision ≥ 0.85 且尽量提高 coverage；当前 human-gold 为 `0/180`，因此尚不能选定或报告该阈值。

---

## 四、研究问题与实验设计

### RQ1：差异分布（描述性）

**问题**：已对齐漏洞数据库中字段级差异的分布与类型构成是什么？

**数据**：全量 8,066 对，全字段

**输出**：
- Table 1：各字段的五类差异分布（绝对数 + 百分比）
- Figure 1：字段 × 差异类型热力图（factual_conflict 比例高亮）
- 关键发现：severity 和 affected_versions 是高冲突字段；大量"不同"并非 factual_conflict

**预期结论**：
- severity FC 率约 21.7%（1,749/8,066）
- affected_versions FC 率约 8.1%（651/8,066），但在有版本信息的对中比例更高
- published 几乎全是 RD 或 TD，不是真正冲突

---

### RQ2：差异类型检测准确率

**问题**：确定性规范化与字段规则能否准确检测并分类字段级差异？

**数据**：差异类型金标（300 实例，全字段分层抽样）

**基线**：
- B1：Raw exact match（不做规范化，直接比较原始值）
- B2：Normalized equality only（只做规范化，不做类型细分，输出 same/different）
- B3：Simple heuristics（只做 EQ/INC/FC 三分类，无 RD/TD 区分）

**方法**：完整五分类确定性规则（当前 `build_field_discrepancies.py`）

**指标**：
- Overall accuracy（五分类）
- Macro-F1
- Per-type F1（重点关注 FC 的 precision，避免误判）
- Per-field F1

**消融**：
- 去掉规范化层 → 观察 RD 类的 recall 变化
- 去掉 affected_versions 的 4 条收紧规则 → 观察 FC precision 变化

**预期结论**：
- 规范化显著优于原始精确匹配（RD 类 recall 提升明显）
- 五分类比 same/different 更能解释真实差异（FC precision 更高）
- affected_versions 的 4 条收紧规则将 FC 误判率降低约 40%

---

### RQ3：裁决性能与拒判收益

**问题**：证据驱动裁决 + 拒判能否提升 factual_conflict 字段的融合可信性？

**数据**：裁决金标计划（180 FC 实例，severity 80 + affected_versions 100；当前 final 行为 0）

**基线**：
- B1：Always-NVD（直接信任 NVD 字段值）
- B2：Always-GHSA（直接信任 GHSA 字段值）
- B3：Recency（选最近更新的来源）
- B4：No-abstention scoring（用证据评分但不拒判，强制输出）

**方法**：完整证据评分 + 拒判

**指标**：
- Adjudication accuracy（在已裁决样本上）
- Coverage（裁决样本占总 FC 样本的比例）
- Selective accuracy（= accuracy on decided samples，核心指标）
- Abstention rate
- Error rate（= 1 - selective accuracy，越低越好）

**消融**：
- 去掉 Authority score
- 去掉 Freshness score
- 去掉 Agreement score
- 去掉 abstention（= B4 基线）

**预期结论**：
- 证据评分优于固定来源优先（Always-NVD/GHSA）
- 不拒判会在低证据样本上带来明显错误（B4 error rate 高）
- abstention 能在牺牲少量 coverage 的前提下显著提升 selective accuracy

**当前诊断边界（2026-07-15）**：上述内容仍是预期/计划，不是已验证结论。现已从 651 条 affected_versions FC 中排除旧开发 100 条，在剩余 551 条中冻结新的 CVE-disjoint 100 条 holdout；独立证据 cache、盲 worklist和 18 方法 sealed predictions 均在双 Codex 裁决前完成。两个 reviewer 的 discrepancy/source 精确一致为 `42/100`、`53/100`，kappa `0.2679/0.3919`；严格联合确定仅 `35/100`。预注册 all-strict 指标中 branch/artifact fixed fallback 均为 `17/35=0.4857`，raw 为 `15/35`。但揭封后发现严格 35 条中只有 16 条仍是 factual conflict，另外 19 条是 RD/incomplete；在 post-hoc FC-only 分层上，branch/artifact 为 `7/16=0.4375`，与 Always-GHSA、Recency 的 `7/16` 持平，raw/canonical 仅 `1/16`。因此 all-strict source accuracy 混合了差异类型检测与来源裁决，不能作为 FC 裁决性能；下一轮必须预注册两个独立 endpoint。human-gold 仍为 `0/180`，当前结果不支持方法提升或生产切换。

---

### 案例分析（必须有，3–5 个）

1. severity FC：NVD=HIGH，GHSA=MEDIUM，证据指向哪个，裁决结果
2. affected_versions FC：版本范围不兼容，证据如何解决
3. 拒判案例：证据不足，为什么不应该强制输出
4. 规范化救回的 RD 案例：原始看起来是冲突，规范化后发现是表示差异

---

## 五、论文结构

目标页数：10–12 页（COSE 单栏，无严格页数限制，但控制在 12 页以内）

### 1. Introduction（约 1.5 页）

叙事线：
- 漏洞数据库是软件安全决策的基础设施，但多源数据库对同一 CVE 的字段值存在大量不一致
- 动机数据：X% 的 CVE 在 severity 上存在 factual_conflict，Y% 在 affected_versions 上（来自 RQ1）
- 现有工作的三个不足：
  - 只检测不裁决（VIEM、Croft 等）
  - 处理非结构化文本而非结构化字段对（aspect-level 系列）
  - 通用真值发现框架，无漏洞领域语义，无拒判（CRH 等）
- 本文贡献（四条）

### 2. Background and Problem Definition（约 1 页）

- 漏洞数据库生态：NVD 与 GHSA 的角色、字段结构、CVE-ID 对齐机制
- Post-alignment discrepancy task 的形式化定义
- 五类差异的定义与示例（每类一个具体 CVE 例子）

### 3. Method（约 2.5 页）

- 3.1 规范化层（各字段规范化规则）
- 3.2 差异类型检测（五分类规则，per-field）
- 3.3 证据检索（来源、检索策略）
- 3.4 证据评分与裁决（评分公式、拒判机制）

### 4. Experimental Setup（约 1 页）

- 数据集描述（NVD/GHSA 规模、对齐结果）
- 金标构建（标注协议、分层抽样策略、分歧处理）
- 基线与指标定义

### 5. Results（约 3 页）

- 5.1 RQ1：差异分布（Table 1 + Figure 1）
- 5.2 RQ2：检测性能（Table 2，含消融）
- 5.3 RQ3：裁决与拒判（Table 3 + 消融 + 案例分析）

### 6. Discussion（约 0.5 页）

- 为什么差异类型化是必要的（不类型化会导致什么错误）
- 拒判的实践意义（强制裁决的代价）
- 局限性：只覆盖 NVD↔GHSA，金标规模有限

### 7. Threats to Validity（约 0.5 页）

- 内部效度：规则覆盖不完整，金标标注主观性
- 外部效度：只有一个来源对，结论不能直接推广
- 构念效度：五分类体系的边界定义
- 复现性：数据和代码开放

### 8. Related Work（约 1 页）

- 漏洞数据库不一致研究（VIEM、Croft、The Flaw Within 等）
- Aspect-level 差异检测（TOSEM 2023、VuldiffFinder 等，明确区分输入类型）
- 真值发现（CRH、Survey）
- 选择性预测（NeurIPS 2024）

### 9. Conclusion（约 0.25 页）

---

## 六、执行阶段

### Phase D：标注规范与金标建设（当前阶段）

完成标准：
- 形成 annotation guideline（含每类差异的判定规则和边界案例）
- 从 8,066 对中分层抽样 300 个字段实例完成差异类型标注
- 冻结样本最初从 severity FC（1,749）和修复前 affected_versions FC（652）中抽取；输入刷新后 100 条 affected_versions 样本仍全部属于当前 651 条 FC，待构建 180 个现实人类裁决金标实例（severity 80 + affected_versions 100）
- 记录 baseline 的典型误判模式，决定是否继续收紧规则

关键决策点：
- 如果 affected_versions FC 的人工核查误判率 > 30%，需要继续收紧规则再进入 Phase E
- 如果 severity FC 的人工核查误判率 > 20%，需要检查 severity 规范化映射

### Phase E：证据驱动裁决实现

完成标准：
- 明确证据检索策略（从 references 字段提取 advisory 链接）
- 实现证据评分模块
- 在裁决金标子集上输出裁决值、证据、置信度与拒判标记
- 在验证集上确定拒判阈值 θ

### Phase F：实验汇总与论文写作

完成标准：
- RQ1/RQ2/RQ3 对应表格与图已生成
- 论文初稿完成
- Threats to Validity 和 Related Work 写完
- 投稿版润色完成

### 时间节点

| 阶段 | 目标完成时间 |
|------|-------------|
| Phase D | 2026-05-15 |
| Phase E | 2026-06-15 |
| Phase F | 2026-07-31 |
| COSE 投稿 | 2026 Q3 |

---

## 七、风险与控制

| 风险 | 概率 | 控制 |
|------|------|------|
| affected_versions FC 误判率仍高 | 中 | 人工核查后决定是否继续收紧，或在论文中明确报告误判率并分析原因 |
| 裁决金标证据覆盖率低（大量 FC 无可用证据） | 高 | 只对有证据的子集建金标，abstain 率高本身就是一个发现 |
| 单人标注被审稿人质疑 | 中 | 对 20% 样本做二次核查，报告分歧率；在 Threats to Validity 中说明 |
| COSE 审稿人认为与 VuldiffFinder 重复 | 中 | Related Work 中明确区分：VuldiffFinder 输入是非结构化文本，本文输入是结构化字段对 |

---

## 八、COSE 版本的贡献边界（为 Plan A 预留空间）

COSE 版本明确不做以下内容，这些留给 Plan A：
- 裁决问题的形式化（precision-constrained coverage maximization）
- affected_versions 的证据解析子任务（从 advisory 文本中解析版本约束）
- 下游 vulnerable package matching 实验
- 多来源对泛化性实验

在 COSE 论文的 Future Work 一节中明确指出这三个方向，为 Plan A 的 ICSE 投稿建立叙事连接。
