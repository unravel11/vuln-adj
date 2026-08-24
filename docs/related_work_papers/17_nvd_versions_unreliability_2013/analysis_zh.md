# NVD Vulnerable Versions Reliability：全文解析

**证据等级**：全文 PDF，8 页；arXiv:1302.4133，2013。

## 1. 论文一句话定位

论文以 Google Chrome 漏洞为对象，逐版本核查 NVD 声称的受影响版本，展示版本数据错误如何改变经验研究结论。

## 2. 论文要解决的问题

作者观察到 NVD 数据会让大量 Chrome 漏洞似乎从首个版本开始一直存在，于是质疑 affected-version 声明的可靠性。gap 是把“异常分布”推进到逐版本经验核查，并检查错误对 foundational vulnerability 研究的影响。

## 3. 核心贡献拆解

全文可确认其构造 Chrome 发布/漏洞关系，验证 NVD 列出的版本是否实际受影响，发现若干错误，并重算下游分析。贡献是早期、具体地证明版本元数据错误会改变研究结论；范围仅是当时的 Chrome/NVD，不能外推当前全库 prevalence。

## 4. 方法揉碎讲解

作者把 NVD CPE/版本声明映射到 Chrome releases，利用漏洞修复与版本历史判断每个版本的状态，再比较原始与修正数据上的统计。版本映射负责 identity，修复历史负责 boundary，重分析负责 consequence。假设是修复记录能界定受影响范围，Chrome release 历史完整。

## 5. 实验逻辑

实验先诊断异常，再人工/证据核查，最后做 sensitivity analysis。这个证据链比只看跨库差异更接近事实，但单项目样本和旧 schema 限制一般性。它不是自动分类算法，没有可直接复现到五字段的 baseline 指标。

## 6. 论文真正证明了什么

强结论是其核查样本中的 NVD Chrome 版本数据存在错误。中等结论是这些错误足以改变一项经验研究的结论。它不证明 NVD 普遍劣于其他数据库，也不证明 GHSA 值正确。

## 7. 局限与风险

2013 年数据、单项目、版本历史解释与修复即边界的假设限制外推。现代 package ecosystem、backport 和多个 artifact 更复杂。

## 8. 可复述版本

10 秒版：affected_versions 错误会把研究结论带偏。组会版：它是本项目输入审计和 failure analysis 的强动机，但不是正向 adjudication 证据。

## 9. 对本项目的可迁移点

可借鉴逐版本 evidence reconstruction 和“原始 vs 修正”敏感性分析。若未来恢复 T3，应选少量可识别项目做真实发布图 gold；当前 no-go 不能被该论文替代。

## 10. 审稿式评价

**Strengths**：从异常到事实核查再到 downstream impact。**Weaknesses**：范围窄且年代久。**Questions**：在当前 NVD 2.0 与 GHSA/OSV range 表达下同类错误是否仍存在？
