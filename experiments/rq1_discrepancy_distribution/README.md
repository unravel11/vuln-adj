# RQ1: Discrepancy Distribution

目标：

- 统计字段可用性
- 统计 discrepancy rate
- 分析各字段的类型分布

建议后续放入：

- 数据加载与字段抽取脚本
- 基础统计配置
- 绘图入口

## 当前入口

- `python3 experiments/rq1_discrepancy_distribution/bootstrap_field_coverage.py`
  - 读取 `data/processed/bootstrap/aligned/nvd_ghsa_by_cve.jsonl`
  - 输出 bootstrap 阶段的对齐覆盖、按年份匹配率、字段覆盖摘要
  - 结果写入 `results/rq1_discrepancy_distribution/`
