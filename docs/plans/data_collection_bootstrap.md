# 数据收集与清洗启动方案

当前收缩目标：

- 主数据源仅保留 `NVD ↔ GHSA`
- 先服务于 `RQ1 / RQ2 / RQ3`
- 先收敛四个主字段：`version`、`severity`、`date`、`references`

## 原始数据入口

- NVD：使用仓库内已有 `data/raw/nvdcve-2.0-2023.json` 与 `data/raw/nvdcve-2.0-2024.json.zip`、`data/raw/nvdcve-2.0-2025.json.zip`
- GHSA：直接使用 `github/advisory-database` 的官方 snapshot

## 新增脚本

- [fetch_ghsa_snapshot.py](/Users/unravel/code/vuln-adj/scripts/fetch_ghsa_snapshot.py)
  - 下载 GHSA snapshot tarball
  - 可选解压到 `data/raw/ghsa/advisory-database/`
- [build_initial_corpus.py](/Users/unravel/code/vuln-adj/scripts/build_initial_corpus.py)
  - 读取 NVD 原始文件
  - 读取 GHSA snapshot 或解压目录
  - 输出统一 JSONL
  - 基于 `CVE-ID` 产出初始对齐文件

## 当前统一输出

- `data/processed/bootstrap/nvd/nvd_2023_2025.normalized.jsonl`
- `data/processed/bootstrap/ghsa/ghsa.normalized.jsonl`
- `data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl`
- `data/processed/bootstrap/manifests/bootstrap_summary.json`

## 当前抽取字段

- 公共标识：`source`、`source_id`、`cve_id`、`aliases`
- 时间：`published`、`last_modified`
- 严重性：`metric_key`、`score`、`label`、`vector`
- 弱点：`cwe_ids`
- 引用：`references`
- 受影响对象：`affected`

## 当前边界

- NVD 通过 `jq` 流式抽取 `vulnerabilities[].cve`，避免一次性把全年 JSON 全部载入内存
- GHSA 第一版优先读取官方 snapshot，不依赖本机 git 的代理配置
- 当前只做“可比较的统一抽取”，不在这一步强行完成 version-range 语义归并或 discrepancy typing
