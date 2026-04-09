# vuln-adj

字段级漏洞信息差异检测与证据驱动裁决研究仓库。

当前目标：

- 保存实验与论文规划，统一管理研究资产
- 搭建代码、数据、标注、结果与论文目录
- 以 `NVD ↔ GHSA` 为主实验线，逐步补充 `CNVD / CNNVD` 压力测试
- 目标投稿期刊暂定为 `Computers & Security (COSE)`

## 仓库结构

- `docs/plans/`: 研究计划、实验规划与里程碑
- `paper/`: 论文写作目录
- `paper/cose/`: 面向 COSE 组织的论文草稿、图表与章节材料
- `experiments/`: 各研究问题对应的实验目录
- `data/`: 原始数据、处理后数据与标注数据说明
- `scripts/`: 数据处理、规范化、比较、评估等脚本
- `results/`: 实验输出、表格、图与分析结果

## 当前约定

- `paper/cose/` 下维护投稿稿件相关内容
- `experiments/` 按 RQ 划分，避免把所有实验混在单一路径下
- `data/raw/` 默认不直接提交大体量原始数据；提交说明文件与必要的小型样本
- 涉及裁决真值的内容仅在有外部证据时建立，不在仓库中伪造结论

## 下一步建议

1. 补充 `NVD ↔ GHSA` 对齐数据导入与统一 schema 定义
2. 先收敛四个主字段：`version`、`severity`、`date`、`references`
3. 实现 deterministic normalization 与 discrepancy typing 初版
4. 再进入 evidence scoring 与 abstention 模块
