# Scripts

该目录用于放置可复用脚本，例如：

- 数据下载与导入
- schema 映射
- normalization
- 字段比较
- 评估与汇总

优先将通用逻辑放在这里，而不是散落在各实验目录。

## 当前入口

- `python3 scripts/fetch_ghsa_snapshot.py`
- `python3 scripts/build_initial_corpus.py`
- `python3 scripts/build_field_discrepancies.py`

## 字段差异入口

`build_field_discrepancies.py` 当前读取：

- `data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl`

并输出：

- `data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`
- `data/processed/bootstrap/discrepancies/field_discrepancy_stats.json`

当前第一版仅覆盖可直接比较的字段：

- `severity`
- `published`
- `cwe_ids`
- `references`
- `affected_versions`

说明：

- 这是一版 deterministic baseline，不包含证据抓取或人工裁决。
- `references` 与 `affected_versions` 采取保守规则，优先减少把表示差异误判成事实冲突。
