# 项目总计划

更新时间：2026-04-21

## 1. 当前目标

围绕 `NVD ↔ GHSA` 主线，完成以下闭环：

1. 建立可复用的数据收集、清洗与对齐管线
2. 建立统一字段视图与 deterministic discrepancy typing baseline
3. 构建小规模人工标注规范与抽样验证集
4. 在冲突字段上实现证据驱动裁决与拒判
5. 形成可写入 `COSE` 稿件的实验结果与论文材料

## 2. 当前范围

- 主数据源：`NVD ↔ GHSA`
- 主研究问题：`RQ1 / RQ2 / RQ3`
- 主字段：`severity`、`published/date`、`references`、`affected_versions`
- 补充字段：`cwe_ids`
- 暂不把 `CNVD / CNNVD` 纳入主执行线

## 3. 阶段计划

### 阶段 A：仓库与研究资产落盘

状态：`已完成`

完成标准：

- 仓库结构、论文目录、实验目录、计划目录已建立
- 目标期刊与当前主线已在仓库内固定

### 阶段 B：原始数据收集、清洗与初始对齐

状态：`已完成`

完成标准：

- NVD 2023–2025 已规范化
- GHSA snapshot 已落地并可读取
- 基于 `CVE-ID` 的初始对齐文件已生成

### 阶段 C：统一字段视图与差异检测 baseline

状态：`已完成`

完成标准：

- 对齐对中的可比字段已映射到统一视图
- 字段级 baseline 标签已可批量生成
- 字段级统计文件已可导出

### 阶段 D：标注规范与抽样验证

状态：`进行中`

完成标准：

- 形成 discrepancy typing annotation guideline
- 抽样 50–100 个字段实例完成人工核查
- 记录 baseline 的典型误判模式

### 阶段 E：证据驱动裁决与拒判

状态：`未开始`

完成标准：

- 明确证据源与评分规则
- 在冲突字段子集上输出裁决、证据、置信度与拒判
- 形成可评估的 adjudication 子集

### 阶段 F：实验汇总与论文写作

状态：`未开始`

完成标准：

- 形成 RQ1 / RQ2 / RQ3 对应表格与图
- 把方法、实验、威胁与局限写入 `paper/cose/`

## 4. 近期执行顺序

1. 先做阶段 D：写 annotation guideline，并从当前 `8066` 个匹配对中抽样
2. 基于抽样结果收紧 baseline 规则，尤其是 `affected_versions` 与 `references`
3. 再进入阶段 E，只在 `Temporal Discrepancy` 与 `Factual Conflict` 子集上做证据裁决

## 5. 当前已知风险

- `affected_versions` 的跨源表达差异仍然很大，baseline 结果不能直接当最终冲突结论
- `references` 中存在 URL 形式差异、追踪参数和平台镜像问题，容易高估差异
- 目前还没有人工金标，`RQ2` 只能说“已有 baseline”，不能说“已验证准确”
