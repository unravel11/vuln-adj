# Related Work Evidence Archive

**更新时间**：2026-08-24
**检索截止**：2026-08-24

本目录保存 NVD–GHSA 字段差异、漏洞元数据质量、冲突消解、拒判/转交和公开数据集相关论文。每个条目都有独立 `analysis_zh.md`；报告区分作者主张、全文可确认事实、读者推断和证据缺口。

## 当前证据状态

- 纳入论文：`24`
- 已取得并核验全文 PDF：`23`
- 摘要/元数据级、全文未取得：`1`（`18_cvss_bayesian_tdsc_2018`）
- 独立中文解析：`24/24`
- 机器可读来源/页数/哈希清单：`literature_manifest.json`
- 跨论文总结：`../related_work_synthesis_20260824.md`
- JSS framing 与实验缺口：`../../paper/jss/FRAMING_AND_EXPERIMENT_GAP_REVIEW_20260824.md`

## 条目索引

| ID | 简称 | 路线 | 证据 |
|---|---|---|---|
| 01 | VIEM | 文本–NVD 版本差异 | 全文 PDF |
| 02 | Croft severity | 跨生命周期 severity | 全文 PDF |
| 03 | Flaw Within | NVD 内部 CVSS 审计 | 全文 PDF |
| 04 | Cleaning NVD | 单库多字段质量/修正 | 全文 PDF |
| 05 | Affected Versions Benchmark | 同字段工具 benchmark | 全文 PDF |
| 06 | CVSS User Study | 人因与评分构念 | 全文 PDF |
| 07 | TOSEM Aspect Discrepancy | 直接竞争：文本 aspect 差异 | 全文 PDF |
| 08 | LLM Aspect Discrepancy | LLM 抽取/差异 | 全文 PDF |
| 09 | VuldiffFinder | 直接竞争：非结构化漏洞差异 | 全文 PDF |
| 10 | GapFinder | CTI 语义不一致 | 全文 PDF |
| 11 | CRH | 通用 truth discovery | 全文 PDF |
| 12 | Truth Discovery Survey | 方法论综述 | 全文 PDF |
| 13 | GHSA Review Pipeline | 平台审核/时序机制 | 全文 PDF |
| 14 | VulZoo | 多源数据集 | 全文 PDF |
| 15 | VEX Tools | 下游工具一致性 | 全文 PDF |
| 16 | HSC | 层次选择性分类 | 全文 PDF |
| 17 | NVD Chrome Reliability | affected-version 事实核查 | 全文 PDF |
| 18 | Bayesian CVSS | 潜在真值/来源质量 | 摘要-only，closed access |
| 19 | Automated Curation | 属性生成与人工成本 | 全文 PDF |
| 20 | Anatomy of VDB | JSS 系统映射 | 全文 PDF |
| 21 | VFCFinder | 修复链接补全 | 全文 PDF |
| 22 | Data Quality for SV Datasets | 数据质量与模型敏感性 | 全文 PDF |
| 23 | Learning to Defer | 系统级转交效用 | 全文 PDF |
| 24 | CVEfixes | CVE–修复代码 lineage | 全文 PDF |

## 验证与边界

运行 `python3 scripts/build_related_work_manifest.py` 会检查每篇全文目录恰有一个 PDF、逐篇解析包含十个必需章节，并重算 PDF 页数、文本词数、字节数和 SHA-256。该验证证明文件和报告完整，不证明论文结论正确、项目 framing 成立或当前可投稿。

PDF 继续按仓库 payload policy 保留在权威机器并被 Git 忽略；其字节由本清单和仓库总 payload manifest 共同绑定。最终投稿前需补取第 18 篇全文，并刷新 2025–2026 preprint 的出版元数据。
