# Experiments

按研究问题组织实验代码与说明。

## 目录

- `rq1_discrepancy_distribution/`: 差异分布统计
- `rq2_discrepancy_typing/`: 字段级差异检测与类型判定
- `rq3_adjudication/`: 证据驱动裁决与拒判
- `holdout/`: affected_versions CVE-disjoint 冻结评估、盲 worklist、预测预密封和双 Codex 严格合并；不是 human-gold
- `simulated_expert_validation/`: 本地 simulated-expert fallback 的 proxy 指标，不能作为 human-gold 结果
- `rq4_stress_test/`: 跨语言 / 高缺失压力测试
- `configs/`: 实验配置、字段映射、规则参数

## 组织原则

- 每个子目录优先包含自己的 `README`
- 能复用的通用逻辑再抽到 `scripts/`
- 结果文件不直接混入代码目录
