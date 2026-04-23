# 项目进度日志

## 2026-04-21

### 1. 完成：原始数据清洗与初始对齐

产物：

- `/Users/unravel/code/vuln-adj/data/processed/bootstrap/nvd/nvd_2023_2025.normalized.jsonl`
- `/Users/unravel/code/vuln-adj/data/processed/bootstrap/ghsa/ghsa.normalized.jsonl`
- `/Users/unravel/code/vuln-adj/data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl`
- `/Users/unravel/code/vuln-adj/data/processed/bootstrap/manifests/bootstrap_summary.json`

验证：

- 规范化与对齐脚本已实际运行
- 汇总清单已落盘，可直接核查记录数

当前效果：

- NVD 规范化记录数：`100032`
- GHSA 规范化记录数：`28785`
- 对齐总行数：`100032`
- 按 `CVE-ID` 匹配到 GHSA 的行数：`8066`

未验证：

- 当前只验证了“数据已可读、可对齐”，还未验证字段级差异标签准确性

下一步：

- 基于对齐结果构建统一字段视图和 discrepancy typing baseline

### 2. 完成：统一字段视图与字段级差异 baseline

产物：

- `/Users/unravel/code/vuln-adj/scripts/build_field_discrepancies.py`
- `/Users/unravel/code/vuln-adj/data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`
- `/Users/unravel/code/vuln-adj/data/processed/bootstrap/discrepancies/field_discrepancy_stats.json`

验证：

- 脚本已通过 `py_compile`
- 脚本已在当前对齐文件上实际运行并生成输出

当前效果：

- 处理匹配对数量：`8066`
- `severity`：`3106 equivalent`，`3178 representation_discrepancy`，`1749 factual_conflict`
- `published`：`6169 representation_discrepancy`，`1897 temporal_discrepancy`
- `cwe_ids`：`6813 equivalent`，`1146 incomplete`，`84 factual_conflict`
- `references`：`7763 incomplete`，`300 representation_discrepancy`，`3 factual_conflict`
- `affected_versions`：`424 equivalent`，`3311 representation_discrepancy`，`3059 incomplete`，`1272 factual_conflict`

未验证：

- 这是一版 deterministic baseline，不是人工验证后的最终差异类型结果
- `affected_versions` 与 `references` 仍可能存在规则误判

下一步：

- 编写 annotation guideline，并抽样人工核查 50–100 个字段实例

## 2026-04-22

### 1. 完成：收紧 `affected_versions` baseline 误判规则

产物：

- `/Users/unravel/code/vuln-adj/scripts/build_field_discrepancies.py`
- `/Users/unravel/code/vuln-adj/data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`
- `/Users/unravel/code/vuln-adj/data/processed/bootstrap/discrepancies/field_discrepancy_stats.json`

验证：

- 脚本已通过 `py_compile`
- 脚本已在 `/Users/unravel/code/vuln-adj/data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl` 上实际重跑
- 输出统计文件与字段视图文件已重新落盘，可直接核查

当前效果：

- `affected_versions`：`424 equivalent`，`3931 representation_discrepancy`，`3059 incomplete`，`652 factual_conflict`
- 相比上一版，`affected_versions.factual_conflict` 从 `1272` 降到 `652`
- 本次新增并实际触发的降级规则包括：
- `221` 条：`end_including` vs `end_excluding/fixed` 且共享 `major.minor` 前缀
- `253` 条：NVD 点版本落在可解析的 GHSA 范围内
- `141` 条：`end_excluding` 字符串前缀截断
- `5` 条：NVD 使用日期字符串作为 `version_end_excluding`

未验证：

- 这仍是规则收紧后的 deterministic baseline，不是人工金标
- 模式 A 只对 `packaging.version.Version` 可解析的版本做比较；不可解析版本仍保持原判
- “不同包导致的版本体系不一致”尚未在上游对齐阶段修复，本轮未在 `compare_affected_versions` 中自动降级
- 尚未对新的 `652` 条 `factual_conflict` 做人工抽样核查，误判率还未验证

下一步：

- 从新的 `affected_versions.factual_conflict` 中抽样 `100` 条进行人工核查
- 记录仍残留的误判模式，决定是否继续收紧 baseline 或转入 annotation guideline 固化

### 2. 完成：相关工作论文材料落盘（开放获取优先）

产物：

- `/Users/unravel/code/vuln-adj/docs/related_work_papers/`
- `/Users/unravel/code/vuln-adj/docs/related_work_papers/README.md`

验证：

- 已对已保存的 `paper.pdf` 运行 `file`
- 当前目录下已确认有 `13` 个文件被识别为 PDF
- 目录中同时保留了少量无法直接获取全文条目的落地页，便于后续人工补抓

当前效果：

- `docs/related_work_survey.md` 中列出的 `16` 个条目里，`13` 个已落盘为全文 PDF
- `2` 个条目仅保存了落地页：`07_aspect_level_tosem_2023`、`09_vuldifffinder_cose_2025`
- `1` 个条目已定位但当前环境未成功保存：`12_truth_discovery_survey_tbd_2024`

未验证：

- 尚未逐篇核对下载文件是否都是最终出版版；其中部分为 arXiv / accepted version / 作者自存档
- `12_truth_discovery_survey_tbd_2024` 的公开 accepted version 链接在当前环境返回 `HTTP 405`，还未通过浏览器或其他来源复现下载
- ACM / Elsevier 受限条目的全文是否存在其他公开镜像，本轮未做更深的人工检索

下一步：

- 如论文写作需要逐篇精读，先从已落盘的 `13` 篇 PDF 建立笔记或摘录
- 如必须补齐 `07`、`09`、`12` 全文，再用机构访问或作者页面继续补抓
