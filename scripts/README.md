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
- `python3 scripts/build_annotation_samples.py`
- `.venv/bin/python scripts/build_rq3_evidence_samples.py <sample.jsonl>`
- `.venv/bin/python scripts/run_llm_annotation.py <sample.jsonl>`
- `.venv/bin/python scripts/summarize_llm_annotations.py <draft.jsonl> [...]`
- `python3 scripts/build_simulated_expert_validation.py`

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
- `build_initial_corpus.py` 会排除 NVD configuration 中显式标记
  `vulnerable=false` 的 CPE；这些条目表示配置匹配中的非受影响项，不能进入
  affected_versions 受影响范围。

## Phase D 抽样入口

`build_annotation_samples.py` 当前读取：

- `data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`

并输出：

- `data/annotations/phase_d/affected_versions_fc_manual_check.jsonl`
- `data/annotations/phase_d/affected_versions_fc_manual_check.csv`
- `data/annotations/phase_d/severity_fc_adjudication_seed.jsonl`
- `data/annotations/phase_d/severity_fc_adjudication_seed.csv`
- `data/annotations/phase_d/sample_manifest.json`

说明：

- 默认随机种子为 `20260506`，用于保证抽样可复现。
- 输出文件是人工标注模板，不是已完成金标。
- 已有冻结样本需要刷新源上下文时使用
  `python3 scripts/build_annotation_samples.py --preserve-existing`。该模式保留
  sample ID/CVE 映射和标注字段；若某行不再满足原字段/状态抽样条件则直接报错。

## Phase D LLM draft 标注入口

`run_llm_annotation.py` 当前读取：

- Phase D 样本 JSONL
- `docs/prompts/phase_d_llm_annotation_prompt.md`
- 项目根目录 `.env` 中的 `OPENAI_API_KEY`、`OPENAI_BASE_URL`、`OPENAI_MODEL`

并输出：

- `data/annotations/phase_d/llm_drafts/*.llm_draft.jsonl`
- `data/annotations/phase_d/llm_drafts/*.requests.jsonl`

说明：

- 当前流程生成的是 `llm_draft`，不是 gold label。
- Prompt 明确要求：只有 URL、没有证据正文时，不允许裁决为 `nvd` 或 `ghsa`，应 `abstain`。
- `summarize_llm_annotations.py` 可统计 draft 的标签、误判、裁决来源和置信度分布。

## RQ3 silver_v2 证据输入入口

`build_rq3_evidence_samples.py` 当前读取 Phase D/RQ3 样本 JSONL，从
`nvd_context.references` 与 `ghsa_context.references` 提取候选 URL，抓取并缓存每个
URL 的证据视图：

- `title`
- `text_snippet`
- `published`
- `host`
- `fetch_status`
- `fetch_detail`

默认输出：

- `data/annotations/rq3/silver_v2/*.evidence.jsonl`
- `data/annotations/rq3/silver_v2/*.evidence_manifest.json`
- `data/evidence_cache/rq3/url_cache/*.json`

`run_llm_annotation.py` 会把输入样本中的 `evidence_context` 传给模型。生成 RQ3
evidence-aware silver label 时，应使用：

```bash
.venv/bin/python scripts/build_rq3_evidence_samples.py data/annotations/phase_d/severity_fc_adjudication_seed.jsonl
.venv/bin/python scripts/run_llm_annotation.py \
  --prompt-path docs/prompts/rq3_silver_v2_with_evidence_prompt.md \
  --output-dir data/annotations/rq3/silver_v2/llm_silver_v2 \
  data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl
```

说明：

- `silver_v2` 是 evidence-aware LLM silver label，不是人工金标。
- 若 URL 抓取失败或正文片段不足，模型仍应 abstain/uncertain。

## 本地 simulated-expert fallback

`build_simulated_expert_validation.py` 仅用于远端权威目录不可达时的本地恢复/演示：

- 输入：本地 `data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl`、已有 Phase D/RQ3 silver 文件。
- 输出：`data/annotations/simulated_expert/`。
- 覆盖：RQ2 primary `300` 条、RQ2 consistency `60` 条、RQ3 severity `80` 条、RQ3 affected_versions `100` 条。

说明：

- 这些文件明确标注为 `simulation_only=true`、`gold_label_is_human=false`。
- RQ2 标签保留 deterministic baseline 作为 proxy，RQ2 consistency 复制模拟 primary 标签。
- RQ3 severity 使用 evidence-aware `silver_v2` 作为 proxy；RQ3 affected_versions 使用旧 Phase D URL-only LLM draft 作为 proxy。
- 该流程不能替代真实 human-gold validation，也不能解除投稿 blocker。

## Expert candidate 与人工复核入口

`run_expert_candidate_annotation.py` 生成带完整 provenance 的 AI 安全专家候选，不写入 canonical gold。RQ2 默认按五字段 round-robin 调度；`--plan-only` 可预览 pending 顺序，`--max-new-rows` 可限制单次新增行数。

`import_rq2_expert_candidate_batch.py` 用于导入已经逐条复核的 RQ2 结构化决策。它校验 source/value、枚举、evidence URL、版本推理类型和人工复核标志，并拒绝重复 sample ID；输出仍写入隔离的 expert-candidate JSONL，始终保持 `label_is_human=false`。

`build_expert_candidate_review_packets.py` 把已有 candidate 与原始字段上下文合并到：

- `data/annotations/expert_candidate/review_packets/*.review.jsonl`
- `data/annotations/expert_candidate/review_packets/*.review.csv`
- `data/annotations/expert_candidate/review_packets/manifest.json`

复核包默认拒绝覆盖，避免破坏人工编辑。candidate 始终保持 `label_is_human=false`；只有人工标注者、独立 reviewer 和 author sign-off 均完成的行，才可能在后续进入 canonical human-gold。

## 仓库 payload 清单

`build_repository_payload_manifest.py` 为 Git 明确忽略、但仍保留在权威远端的 raw/
processed 数据、results、外部论文 PDF、evidence cache 和历史生成 payload 建立逐文件
SHA-256 清单。默认输出：

- `docs/repository_hygiene/retained_local_payloads.sha256.tsv`

使用 `--verify` 会重新枚举当前 ignored path set，并逐文件核对大小与 SHA-256；新增、
缺失或字节变化都会失败。该校验只提供机械完整性，不提升任何实验或标签主张。
