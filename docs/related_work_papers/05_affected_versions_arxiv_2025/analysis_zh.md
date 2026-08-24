# Vulnerability-Affected Versions Identification：全文解析

**证据等级**：全文 PDF，13 页；arXiv:2509.03876，2025 预印本。

## 1. 论文一句话定位

论文构建人工核验的 C/C++ 漏洞受影响版本 benchmark，并比较多种自动识别工具，研究从修复信息推断 vulnerable version range 到底有多可靠。

## 2. 论文要解决的问题

版本范围不是普通字符串：它依赖项目发布图、修复提交、分支/backport 和 package/product 身份。已有工具使用不同信号，却缺少同一 gold 与同一任务合同上的系统比较。该 gap 属于 benchmark 与评估层。

## 3. 核心贡献拆解

全文可确认其建立 1,128 个 C/C++ 漏洞的标注集并评测 12 个工具；摘要报告人工一致性 Cohen’s kappa 0.83、单工具 accuracy 不超过 45%、集成约 60%。这些值受 C/C++、样本选择、版本定义和工具可运行性限制，不是所有生态的能力上限。

## 4. 方法揉碎讲解

研究先确定漏洞—仓库—修复关系，再人工判断受影响版本，用统一输入运行工具，最后将工具输出投影到 benchmark 合同。工具路线涉及代码差分、版本/标签历史、修复传播或组合证据。真正困难在“版本集合语义”而非格式解析；若 gold 不区分分支和 artifact，比较会失真。

## 5. 实验逻辑

主实验比较工具整体与分组表现，组合实验检验互补性，错误分析定位失败因素。它是目前 affected_versions 最接近的 same-field baseline 资源，但任务是从代码/修复推断真值，不是比较两个数据库字段并分类差异。

## 6. 论文真正证明了什么

强结论是现有工具在该 benchmark 上表现有限且输出互补。中等结论是 affected-version identification 仍需多源证据与明确协议。它不证明本项目规则失败的所有原因，也不证明跨库冲突必然需要自动裁决。

## 7. 局限与风险

预印本状态、C/C++ 范围、人工 gold 的可识别性、仓库/发布证据可得性和工具复现均限制外推。accuracy 数字不能与本项目 selective coverage 或 type agreement 直接比较。

## 8. 可复述版本

10 秒版：受影响版本识别在严格 benchmark 上仍很难，多工具组合也未解决全部问题。组会版：它强化了 affected_versions 应允许 unresolved，而不是支撑“我们已有更好裁决器”。

## 9. 对本项目的可迁移点

可作为 T3 若重启时的同字段外部 baseline 和错误分类参考；应复用其版本/修复证据思想。当前项目没有在同一 benchmark 上复现这些工具，因此不能声称超过它们。

## 10. 审稿式评价

**Strengths**：同任务 benchmark、人工协议和多工具比较。**Weaknesses**：生态与证据可用性边界明显。**Questions**：其 gold 如何处理 backport、未发布修复和多 artifact 坐标？
