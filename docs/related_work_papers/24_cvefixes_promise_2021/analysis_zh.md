# CVEfixes：全文解析

**证据等级**：全文 PDF，10 页；PROMISE 2021，DOI: 10.1145/3475960.3475985；CC BY 4.0，工具与 dataset 公开。

## 1. 论文一句话定位

CVEfixes 自动从 NVD 和开源仓库收集 CVE、漏洞修复提交、修复前后代码及多粒度指标，形成可更新的关系型漏洞数据集。

## 2. 论文要解决的问题

代码级漏洞研究缺少规模大、跨语言、带真实修复和多粒度上下文的数据。gap 是可重复的数据构建管线，而非字段差异检测或数据库裁决。

## 3. 核心贡献拆解

全文可确认初始版本覆盖截至 2021-06-09 的 5,365 个 CVE、1,754 个开源项目和 5,495 个修复提交，并组织 commit、file、method 等层级信息。规模与自动更新是贡献；NVD reference 到仓库/commit 的链接质量仍决定数据正确性。

## 4. 方法揉碎讲解

工具抓取 NVD，筛选开源 repository/reference，定位修复提交，克隆仓库并抽取修复前后变更，再计算语言和代码/安全指标写入关系库。NVD 提供入口，Git history 提供代码事实，schema 提供可查询 lineage。假设是引用指向正确修复、commit parent 代表 vulnerable state、项目历史可获取。

## 5. 实验逻辑

数据集论文以 coverage、语言/项目/漏洞分布和用途展示为主，没有对所有 link 逐例人工精度评估。它是 released dataset/resource baseline，可用于外部证据 enrichment，但不与本项目五分类器在同一输出上竞争。

## 6. 论文真正证明了什么

强结论是作者实现并发布了可重复构建的代码—漏洞数据集。中等结论是它支持多类数据驱动研究。它不证明所有修复链接、affected versions 或 CWE 标签正确。

## 7. 局限与风险

公开仓库选择偏差、reference 缺失、squash/backport、多修复提交和删除仓库会影响 lineage；快照已较旧。将其作为“真值”前必须抽样核查 link 和修复边界。

## 8. 可复述版本

10 秒版：CVEfixes 把 NVD advisory 接到真实修复代码。组会版：它能补充 references/affected_versions 的证据，却不直接解决跨库差异类型。

## 9. 对本项目的可迁移点

可作为 released dataset 和 artifact-graph evidence 来源，并启发对 VFC link 的独立验证。当前实验若未实际复现/接入，不得把它写成已比较 baseline。

## 10. 审稿式评价

**Strengths**：公开管线、跨语言、多粒度 lineage。**Weaknesses**：自动 link 与版本边界缺系统 gold。**Questions**：与 GHSA/VFCFinder 交叉后，reference coverage 与错误率如何变化？
