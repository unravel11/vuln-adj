# Annotations

建议后续维护两类标注：

- discrepancy typing 金标
- adjudication 金标

字段建议至少覆盖：

- version
- severity
- date
- references

裁决样本仅在有明确外部证据时给出真值。

## 当前产物

- `phase_d/affected_versions_fc_manual_check.{jsonl,csv}`：从 `affected_versions.factual_conflict` 中抽样 100 条，用于人工核查 baseline 是否误判。
- `phase_d/severity_fc_adjudication_seed.{jsonl,csv}`：从 `severity.factual_conflict` 中抽样 80 条，用于构建 severity 裁决金标的起始样本。
- `phase_d/sample_manifest.json`：记录输入文件、随机种子、候选数量、抽样数量和产物路径。
- `simulated_expert/`：远端环境不可达时生成的本地模拟专家标注 fallback，覆盖 RQ2 primary `300` 条、RQ2 consistency `60` 条、RQ3 severity `80` 条和 RQ3 affected_versions `100` 条。
- `ai_adjudicated_gold/source_reaudit/`：affected_versions 的非人工双 Codex source re-audit。统一严格 overlay 目前为 `31/100` determinate，所有行均为 `label_is_human=false`。
- `holdout/affected_versions_v1/`：与旧开发 100 条 CVE 零重叠的新 100 条 holdout；证据、盲 worklist、预测预密封和双 Codex 联合裁决已完成，严格候选覆盖 `35/100`，不是 human-gold。

说明：

- 当前 Phase D 文件是待人工填写的标注模板，不是已完成金标。
- `manual_label`、`is_baseline_false_positive`、`adjudicated_source`、`adjudicated_value`、`evidence_urls` 等列需要人工核查后填写。
- `simulated_expert/` 下的文件也不是独立 human-gold；manifest 中明确记录 `simulation_only=true`、`gold_label_is_human=false`，不能用于替代真实 RQ2/RQ3 human-gold validation。
- source re-audit 可作为作者复核候选和方法诊断，不能写入 human annotator/reviewer 字段；现实人类签收仍为 `0/540`。
- holdout 已揭封，不得继续用其结果调参后再声称独立验证；下一轮方法必须使用新的冻结 cohort。
