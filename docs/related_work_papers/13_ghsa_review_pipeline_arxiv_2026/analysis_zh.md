# GHSA Review Pipeline：全文解析

**证据等级**：全文 PDF，12 页；开放全文来自 arXiv:2602.06009。2026-08-25
已由 MSR 2026 官方 Technical Papers 页面核对，正式 DOI
`10.1145/3793302.3793360`；作者公开复现仓库为
`https://github.com/cmsegal/ghsa-review`。

## 1. 论文一句话定位

论文分析 GHSA 的 reviewed 状态与审核延迟，区分 GitHub Repository Advisory 快路径和 NVD-first 慢路径，并用排队模型解释时延。

## 2. 论文要解决的问题

GHSA 既含 GitHub 原生 advisory，也吸收外部/NVD 记录；哪些记录会 reviewed、多久完成审核并不透明。该 gap 属于平台流程与时序机制，而非字段正确性。

## 3. 核心贡献拆解

摘要报告分析超过 288,000 条、覆盖 2019–2025，并识别两个 latency regime。全文可确认其做大规模描述统计、因素分析和 queueing model。reviewed 是流程状态，不等于所有字段经独立事实核验，更不等于 human gold。

## 4. 方法揉碎讲解

作者从 GHSA 元数据重建 advisory 来源、review status 和时间节点，再按 GRA 与 NVD-first 分层，分析延迟分布并拟合队列。分层模块避免把两条生成路径混为一谈；排队模型提供机制解释。假设是公开时间戳能反映内部流程、来源分类正确且删失处理合理。

## 5. 实验逻辑

研究先描述 reviewed coverage/latency，再比较路径，最后用模型解释与预测。它支持 temporal discrepancy 的生成机制，但不是对某个字段差异标签的验证。项目当前 post-freeze GHSA 为零的观察也不能由该论文推出等待时间。

## 6. 论文真正证明了什么

强结论是公开 GHSA 元数据中存在显著不同的审核路径和延迟分布。中等结论是队列模型能解释部分时延。它不证明 reviewed GHSA 比 NVD 更真，也不证明 TD 五分类可靠。

## 7. 局限与风险

平台内部操作不可见、时间戳语义可能变化和 API 选择仍限制解释。正式出版与公开复现仓库改善了可追溯性，但 review status 与字段级 curation depth 仍不能混同。

## 8. 可复述版本

10 秒版：GHSA 的快慢路径会自然产生时序差异。组会版：这支持把一部分差异路由为等待/刷新，而不是立即升级为事实冲突。

## 9. 对本项目的可迁移点

可用于解释 TD 的操作意义，并要求 T2 明确“defer until refresh”动作。不能用作 TD label gold；当前严格 temporal generalization 仍须真实 post-freeze 双边 cohort。

## 10. 审稿式评价

**Strengths**：直接研究 GHSA 流程，机制与数据结合。**Weaknesses**：外部观察无法确认内部审查内容。**Questions**：review 完成后字段更新是否同步，哪些字段延迟最大？
