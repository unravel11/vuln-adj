# Phase D Annotation Samples

本目录保存 Phase D 的可复现抽样产物。

## 文件

- `affected_versions_fc_manual_check.jsonl` / `.csv`
  - 来源：`affected_versions.factual_conflict`
  - 当前候选数：651（2026-07-15 输入完整性修复后；旧 100 条映射保持冻结）
  - 抽样数：100
  - 用途：人工核查 `affected_versions` baseline 的误判率，决定继续收紧规则或固化标注规范。

- `severity_fc_adjudication_seed.jsonl` / `.csv`
  - 来源：`severity.factual_conflict`
  - 候选数：1749
  - 抽样数：80
  - 用途：构建 severity factual-conflict 裁决金标的起始样本。

- `sample_manifest.json`
  - 记录输入文件、随机种子、候选数量、实际抽样数量和输出路径。

## 标注列

- `manual_label`：人工判定的差异类型。建议值：`equivalent`、`representation_discrepancy`、`incomplete`、`temporal_discrepancy`、`factual_conflict`、`uncertain`。
- `is_baseline_false_positive`：当前 baseline 是否把非 FC 误判为 FC。建议值：`yes`、`no`、`uncertain`。
- `adjudicated_source`：裁决支持的来源。建议值：`nvd`、`ghsa`、`both`、`neither`、`abstain`。
- `adjudicated_value`：有明确证据时填写裁决值；证据不足时留空或写 `abstain`。
- `evidence_urls`：支持裁决的外部证据链接，多个链接用分号分隔。
- `evidence_notes`：证据如何支持裁决，或为什么证据不足。
- `annotator_notes`：边界情况、规则问题或需要后续复核的点。

## 当前状态

这些文件只是待人工标注模板。只有在人工填写并复核后，才能作为金标或实验结果使用。

## LLM draft annotation

当前已增加 LLM-assisted draft 标注流程：

- Prompt：`/home/xiaoyuliang/code/vuln-adj/docs/prompts/phase_d_llm_annotation_prompt.md`
- 运行脚本：`/home/xiaoyuliang/code/vuln-adj/scripts/run_llm_annotation.py`
- 汇总脚本：`/home/xiaoyuliang/code/vuln-adj/scripts/summarize_llm_annotations.py`
- Draft 输出目录：`/home/xiaoyuliang/code/vuln-adj/data/annotations/phase_d/llm_drafts/`

运行示例：

```bash
python3 scripts/run_llm_annotation.py data/annotations/phase_d/severity_fc_adjudication_seed.jsonl
python3 scripts/run_llm_annotation.py data/annotations/phase_d/affected_versions_fc_manual_check.jsonl
python3 scripts/summarize_llm_annotations.py data/annotations/phase_d/llm_drafts/*.llm_draft.jsonl
```

约束：

- LLM draft 不是金标。
- 如果输入只有 URL、没有抓取到的证据正文，LLM 不应裁决为 `nvd` 或 `ghsa`，应输出 `abstain`。
- LLM 可用于识别 baseline 可能误判、生成待复核队列和证据核查提示。

当前全量 draft：

- `severity_fc_adjudication_seed` 已完成 80 条 LLM draft。
- `affected_versions_fc_manual_check` 已完成 100 条 LLM draft。
- request 日志可能多于 draft 行数，原因是远端 API 过载、TLS 超时或 SSE 错误触发了断点续跑/重试；最终 draft 文件已校验为样本数完整且 sample_id 无重复。

## RQ3 evidence-aware silver_v2

旧的 LLM draft 输入只有字段值和 URL，不适合直接评估后续证据裁决方法。RQ3
评估用的 `silver_v2` 需要先抓取 `nvd_context.references` 与
`ghsa_context.references` 中的候选 URL，并把证据正文视图写回样本。

当前入口：

```bash
python3 scripts/build_rq3_evidence_samples.py data/annotations/phase_d/severity_fc_adjudication_seed.jsonl
python3 scripts/run_llm_annotation.py \
  --prompt-path docs/prompts/rq3_silver_v2_with_evidence_prompt.md \
  --output-dir data/annotations/rq3/silver_v2/llm_silver_v2 \
  data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl
```

约束：

- `silver_v2` 仍是 silver/draft label，不是人工 gold。
- 只有成功抓取到的证据正文片段可以支撑裁决。
- URL、host 或 title 本身不能当作正文证据。
