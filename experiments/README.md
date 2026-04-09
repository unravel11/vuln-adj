# Experiments

按研究问题组织实验代码与说明。

## 目录

- `rq1_discrepancy_distribution/`: 差异分布统计
- `rq2_discrepancy_typing/`: 字段级差异检测与类型判定
- `rq3_adjudication/`: 证据驱动裁决与拒判
- `rq4_stress_test/`: 跨语言 / 高缺失压力测试
- `configs/`: 实验配置、字段映射、规则参数

## 组织原则

- 每个子目录优先包含自己的 `README`
- 能复用的通用逻辑再抽到 `scripts/`
- 结果文件不直接混入代码目录
