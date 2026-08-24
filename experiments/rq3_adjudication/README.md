# RQ3: Adjudication

目标：

- 建立 evidence scoring
- 支持 abstention
- 与来源优先等基线比较

建议后续放入：

- evidence extraction
- scoring rules
- adjudication evaluation

当前 evidence-aware silver label 流程：

1. 从 RQ3/Phase D 样本的 `nvd_context.references` 与 `ghsa_context.references`
   提取候选 URL。
2. 用 `scripts/build_rq3_evidence_samples.py` 抓取并缓存 URL 证据视图。
3. 将 `evidence_context.records` 写回样本。
4. 用 `docs/prompts/rq3_silver_v2_with_evidence_prompt.md` 重新运行 LLM 标注，
   生成 `silver_v2`。
5. RQ3 裁决方法评估应对比 `silver_v2`，不能再对比只有 URL 输入的旧
   LLM draft。

注意：`silver_v2` 是 evidence-aware LLM silver label，不是人工金标；抓取失败
或正文不足的样本仍应允许 abstain。

当前 baseline 评估入口：

```bash
python3 experiments/rq3_adjudication/evaluate_severity_silver_v2.py
python3 experiments/rq3_adjudication/evaluate_affected_versions_silver_v2.py
```

默认读取：

- `data/annotations/rq3/silver_v2/severity_fc_adjudication_seed.evidence.jsonl`
- `data/annotations/rq3/silver_v2/llm_silver_v2/severity_fc_adjudication_seed.evidence.llm_draft.jsonl`

默认输出：

- `results/rq3_adjudication/severity_silver_v2_predictions.jsonl`
- `results/rq3_adjudication/severity_silver_v2_eval_metrics.json`

当前评估方法均为 baseline：

- `prefer_nvd`：固定选择 NVD。
- `prefer_ghsa`：固定选择 GHSA。
- `latest_published`：选择发布时间更晚的一侧。
- `evidence_score_baseline`：在抓取到的 `title/text_snippet` 中匹配 severity
  label、score、CVSS vector；两侧均有证据则输出 `both`，否则输出有证据的一侧，
  没有足够证据则 `abstain`。

当前远端运行结果（2026-05-14）：

| method | accuracy | macro-F1 | non-abstain coverage |
| --- | ---: | ---: | ---: |
| `prefer_nvd` | `0.325` | `0.1226` | `1.0` |
| `prefer_ghsa` | `0.0375` | `0.0181` | `1.0` |
| `latest_published` | `0.05` | `0.0384` | `1.0` |
| `evidence_score_baseline` | `0.6875` | `0.4317` | `0.9875` |

这些数字只表示在 `silver_v2` 上的 baseline 结果，不是人工 gold 上的最终实验结论。

affected_versions silver_v2 baseline 评估默认读取：

- `data/annotations/rq3/silver_v2/affected_versions_fc_manual_check.evidence.jsonl`
- `data/annotations/rq3/silver_v2/llm_silver_v2/affected_versions_fc_manual_check.evidence.llm_draft.jsonl`

默认输出：

- `results/rq3_adjudication/affected_versions_silver_v2_predictions.jsonl`
- `results/rq3_adjudication/affected_versions_silver_v2_eval_metrics.json`

当前 affected_versions 评估方法均为 baseline：

- `prefer_nvd`：固定选择 NVD。
- `prefer_ghsa`：固定选择 GHSA。
- `latest_published`：选择发布时间更晚的一侧。
- `version_token_support_baseline`：在抓取到的 `title/text_snippet` 中匹配两侧
  affected-version token；两侧均有 token 支持则输出 `both`，否则输出有 token
  支持的一侧，没有 token 支持则 `abstain`。
- `canonical_version_token_support_baseline`：在 token baseline 上规范化版本前缀和
  release qualifier，只接受 release component 数量一致的别名；该规则可识别
  `3.0.0.Final` 与 `3.0.0`，但不会把 `CVSS v4.0` 当作版本 `4.0.0`。
- `contextual_version_claim_baseline` / `contextual_canonical_version_claim_baseline`：
  只保留目标 CVE 页面中靠近 affected/fixed 语义提示的版本 token，并排除已知的
  change-history、branch-selector 和 full-changelog 上下文；后者允许保守 canonical
  alias。它们仍是 lexical baseline，不证明完整范围语义。
- `package_gated_contextual_version_claim_baseline` / canonical 版本：在 contextual
  claim baseline 上增加已有 package gate；包身份不可比时拒判。
- `package_gated_token_baseline`：先检查 NVD 与 GHSA 的包名是否至少能做
  canonical/leaf 对齐；包身份不可比时直接 `abstain`，可比时再应用 token 规则。
- `package_gated_canonical_token_baseline`：先做相同 package gate，再应用 canonical
  token 规则。
- `repository_crosswalk_package_gated_token_baseline` / canonical 版本：若包名没有
  overlap，只在两侧包标识都能锚定同一非通用 GitHub 仓库、且不存在另一侧
  package-specific repository 冲突时恢复可比性，再分别应用 raw/canonical token。
  该规则只支持 package comparability，不证明版本区间或裁决来源正确。
- `package_range_evidence_baseline`：在 package-gated 规则上，仅对可解析且规范化
  后完全相同的区间补充 `both`。inclusive/exclusive 边界的字符串立即后继关系和
  point-in-range 只作诊断；没有真实发布序列时，它们不足以证明两侧区间等价。

当前权威远端运行结果（2026-07-15）：

| method | agreement | macro-F1 | non-abstain coverage | selective agreement |
| --- | ---: | ---: | ---: | ---: |
| `prefer_nvd` | `0.45` | `0.1241` | `1.0` | `0.45` |
| `prefer_ghsa` | `0.11` | `0.0396` | `1.0` | `0.11` |
| `latest_published` | `0.14` | `0.0685` | `1.0` | `0.14` |
| `version_token_support_baseline` | `0.57` | `0.2838` | `0.97` | `0.5876` |
| `canonical_version_token_support_baseline` | `0.57` | `0.2843` | `0.98` | `0.5816` |
| `contextual_version_claim_baseline` | `0.36` | `0.2252` | `0.70` | `0.5000` |
| `contextual_canonical_version_claim_baseline` | `0.46` | `0.2649` | `0.80` | `0.5625` |
| `package_gated_contextual_version_claim_baseline` | `0.18` | `0.1243` | `0.29` | `0.4828` |
| `package_gated_contextual_canonical_version_claim_baseline` | `0.21` | `0.1396` | `0.34` | `0.5000` |
| `package_gated_token_baseline` | `0.32` | `0.2056` | `0.45` | `0.6222` |
| `package_gated_canonical_token_baseline` | `0.30` | `0.1936` | `0.45` | `0.5778` |
| `repository_crosswalk_package_gated_token_baseline` | `0.39` | `0.2403` | `0.54` | `0.6481` |
| `repository_crosswalk_package_gated_canonical_token_baseline` | `0.39` | `0.2394` | `0.55` | `0.6364` |
| `package_range_evidence_baseline` | `0.32` | `0.2056` | `0.45` | `0.6222` |

该评估还输出 audit split：`42` 条 adjudicable positive conflict、`46` 条
adjudicable negative/non-conflict、`12` 条 manual-review/excluded。所有指标仍只是
evidence-aware LLM silver 上的 baseline 结果，不是人工 gold 结论；token baseline
不是语义版本范围裁决器。package gating 提高了已覆盖样本上的一致率，但覆盖率从
`0.97` 降至 `0.45`，且总体一致率低于 token baseline；这是 selective
risk-coverage trade-off，不是整体性能提升。canonical token 相对原 token 只增加
`0.01` coverage，总体 agreement 不变，selective agreement 略降；package-gated
canonical token 反而更差。区间规则在当前输入上没有带来可验证增益，仍需
human-gold 验证后才能评价其有效性。

repository crosswalk 将 package-comparable 样本从 `45/100` 提高到 `56/100`。
但在 `40` 条确定 AI-gold 上，raw crosswalk 的 accuracy 仍为 `0.35`，coverage
从 `0.65` 提高到 `0.725` 时 selective accuracy 从 `0.5385` 降至 `0.4828`；
canonical crosswalk 为 accuracy `0.375`、coverage `0.75`，相对 direct canonical
的 accuracy 增量 `+5pp` 的 bootstrap 区间为 `[0,+12.5]pp`。因此当前结果只证明
repository identity 能恢复部分可比性，不能证明版本来源裁决得到稳定改进。

2026-07-15 的定向盲审进一步选择 raw/canonical 决策不同的 `10` 条样本，由两个
隔离的同模型家族 Agent 只读缓存证据。两者对 canonical-match verdict 和推荐匹配
策略均为 `10/10` 一致，但 discrepancy label 仅 `4/10`、adjudicated source
`7/10` 一致。在这 `7` 条来源共识上，raw token 命中 `4` 条、unrestricted
canonical token 命中 `1` 条、package-gated contextual canonical 命中 `4` 条；
后者在全体 `100` 条上的覆盖率只有 `0.34`。因此 canonical token 目前只适合作为
证据特征，不能作为完整版本范围裁决器；context filter 与 package gate 也尚未形成
可选定的最终方法。该盲审仍是 dual-AI candidate diagnostic，不是 human-gold。

## Affected_versions input integrity

2026-07-15 的输入完整性修复过滤了 NVD configuration 中显式标记
`vulnerable=false` 的 CPE。运行：

```bash
python3 experiments/input_integrity/analyze_affected_versions_input_integrity.py
```

输出：

- `results/input_integrity/affected_versions/affected_versions_input_integrity.json`
- `results/input_integrity/affected_versions/affected_versions_input_integrity.md`

旧语料中的 `1,105` 个 false CPE 涉及 `106/8,066` 条 matched rows，修复后改变
`10` 条全量 baseline 分类。冻结的 100 条 affected_versions 样本有 7 条输入变化，
但样本映射、`40` determinate / `60` abstain 分布和最终决策均未变化。该复核仍为
AI provenance（`label_is_human=false`），不能写作 human validation。当前 GHSA snapshot
未发现 multi-event range，但这不保证未来 snapshot 的首 event 展平逻辑安全。

## Release-boundary feature diagnostic

特征提取与 AI-gold 评估分开运行：

```bash
python3 experiments/rq3_adjudication/test_affected_versions_release_boundary.py
python3 experiments/rq3_adjudication/extract_affected_versions_release_boundaries.py
python3 experiments/ai_adjudicated_gold/evaluate_affected_versions_release_boundaries.py
```

特征文件只读取 100 条 evidence rows，不读取 gold：

- `results/rq3_adjudication/release_boundary/affected_versions_release_boundary_features.jsonl`
- `results/rq3_adjudication/release_boundary/affected_versions_release_boundary_features_summary.json`

评估输出：

- `results/ai_adjudicated_gold/release_boundary/affected_versions_release_boundary_ai_gold_diagnostic.json`
- `results/ai_adjudicated_gold/release_boundary/affected_versions_release_boundary_ai_gold_diagnostic.md`

修正句界 cue binding 后，release-boundary 单独在 40 条确定 AI-gold 上命中
`22/40`，coverage `0.95`；固定 boundary→crosswalk canonical 组合命中 `23/40`。
相对 unrestricted canonical token 的 `+7.5pp` 区间为 `[-12.5,+27.5]pp`，有
14 个改进和 11 个回退，exact paired p=`0.6900`。它能命中旧七方法共同失败中的
`11/17`，使事后并集从 `23/40` 到 `34/40`，但该并集不可部署，实验方向也由旧
失败样本驱动。当前实现只是 CVE-local lexical role 与可解析区间包含诊断，不是
完整 release graph，不切换生产默认。

## Branch/release-graph exploratory diagnostic

```bash
python3 experiments/rq3_adjudication/test_affected_versions_branch_graph.py
python3 experiments/rq3_adjudication/extract_affected_versions_branch_graph.py
python3 experiments/ai_adjudicated_gold/evaluate_affected_versions_branch_graph.py
```

特征输出：

- `results/rq3_adjudication/branch_graph/affected_versions_branch_graph_features.jsonl`
- `results/rq3_adjudication/branch_graph/affected_versions_branch_graph_features_summary.json`

评估输出：

- `results/ai_adjudicated_gold/branch_graph/affected_versions_branch_graph_ai_gold_diagnostic.json`
- `results/ai_adjudicated_gold/branch_graph/affected_versions_branch_graph_ai_gold_diagnostic.md`

该候选只增加三类 gold-blind 结构事件：不透明版本区间中的安全例外、相邻预发布
边界、明确受影响终点与开放区间冲突。它只改变 `4/100` 条预测；在 40 条确定
AI-gold 上单独命中 `25/40`、coverage `0.975`，固定 crosswalk canonical fallback
命中 `26/40`。相对 release-boundary fallback 增加 3 个命中且无回退，但 95%
区间为 `[0,+15]pp`、exact paired p=`0.25`；相对 canonical token 的增量为
`+15pp`，区间仍跨 0。它命中旧共同失败中的 `14/17`，使事后并集达到 `37/40`。
这些规则是在残余误例检查后设计的，仍未解决来源权威、时序修订、多分支快照、
backport 和生态特定排序，因此只是 post-hoc candidate，不切换生产默认。

## Strict source re-audit overlay

隔离 source re-audit 对 45 条 prior-abstain、但曾有非 abstain source suggestion 的
记录刷新证据，并由两个互不可见的 Codex Agent 按更严格的正证据合同独立复核。
缺失证据或抓取失败不能作为反证。完整流程和 provenance 见
`experiments/ai_adjudicated_gold/README.md` 与
`data/annotations/ai_adjudicated_gold/source_reaudit/README.md`。

prior-abstain 45 条上，两个 Agent 的 source decision 精确一致为 `36/45`，kappa
`0.3982`；严格合同只接受 4 条，且均为 `both`。原 40 条确定行随后由两个新 Agent
按相同合同重跑，精确一致 `29/40`、kappa `0.6502`，严格接受 `27` 条；其中样本
`029` 从 `both` 改为 `nvd`，`092` 从 `nvd` 改为 `ghsa`。两部分组成当前统一严格
overlay：`31/100` determinate、`69/100` abstain。历史 `44/100` mixed-contract
overlay 仅保留作审计，不再作为当前方法对比基准。

Agent A 的原始 40 行输出因字段类型不符合 schema 被拒绝，恢复后只做格式转换；
Agent B 披露在 schema 检查时看到了首条完整 candidate object。它声明没有把 prior
source 当作证据，但不能声称完美盲审。所有行仍为 `label_is_human=false`，不切换
生产默认。

## Artifact-bound v2 and uniform benchmark

```bash
python3 experiments/rq3_adjudication/test_affected_versions_artifact_graph.py
python3 experiments/rq3_adjudication/extract_affected_versions_artifact_graph.py
python3 experiments/ai_adjudicated_gold/evaluate_affected_versions_artifact_graph.py
python3 experiments/ai_adjudicated_gold/analyze_artifact_graph_evidence_snapshot_stability.py
python3 experiments/ai_adjudicated_gold/analyze_artifact_graph_uniform_strict_failures.py
python3 experiments/ai_adjudicated_gold/evaluate_affected_versions_uniform_strict_methods.py
```

artifact-bound v2 只在两个来源各自的 CVE-scoped record 中同时出现来源专属 artifact
alias 和版本 token 时，才把 branch graph 的 `abstain/neither` 改为 `both`；不覆盖
单边判断。6 个 focused tests 已通过。该规则修复严格新增的 4 个跨 artifact 样本，
但在 selection-aware 统一证据输入和统一严格 31 行 overlay 上，完整排名为：raw token
`18/31=0.5806`、canonical token `17/31=0.5484`、artifact v2 `16/31=0.5161`、
branch graph `12/31=0.3871`。两个 package selective baseline 并列为
`12/19=0.6316`，prediction coverage `19/31=0.6129`。

证据刷新使 branch raw 预测改变 `15/100`；在旧 44 行 cohort 上，branch fallback
由 26 个命中降至 19 个，artifact fallback 由 30 个降至 23 个。31 行上的 5 个
canonical/artifact 共同失败中，4 个 gold 为 `ghsa`，指向 source authority、temporal
revision 和 package-local structured range parsing，而不是继续增加 token 特例。当前
结果是 post-hoc、非独立、非人工诊断，不支持 graph 方法提升或泛化结论。

## CVE-disjoint holdout

新的 `affected_versions_v1` holdout 从当前 651 条 FC 候选中排除旧开发 100 条，
在剩余 551 条中按固定 SHA-256 rank 冻结 100 条。专用 evidence cache、字段 allowlist
盲 worklist 和 18 方法无标签预测均在两个新 Codex reviewer 输出前完成并密封。完整
合同与命令见 `experiments/holdout/README.md`。

两个 reviewer 的 discrepancy/source 精确一致为 `42/100`、`53/100`，kappa
`0.2679/0.3919`；严格联合 determinate 仅 `35/100`。预注册 all-strict 指标中，
branch/artifact fixed fallback 均为 `17/35=0.4857`，canonical 为 `16/35`，raw、
branch raw 和 artifact raw 均为 `15/35`。

揭封后的 post-hoc task split 发现严格 35 条中只有 16 条仍为 factual conflict，
另外 17 条是 representation discrepancy、2 条是 incomplete。16 条 FC 的来源为
`7 ghsa`、`5 nvd`、`4 neither`；branch/artifact 为 `7/16=0.4375`，但
prefer-GHSA 和 latest-published 也为 `7/16`，raw/canonical 只有 `1/16`。因此旧
all-strict source accuracy 混入了非冲突识别，不能解释为 FC source adjudication。
当前 affected_versions 方法没有超过固定来源基线；本 holdout 已揭封，不得用于后续
调参后的独立验证。所有 reviewer/consensus 行仍为 `label_is_human=false`。

## Task-separated development diagnostic

为 v2 预注册协议实现了两个独立预测头：先做 package-local 结构化区间关系的
discrepancy typing；FC source head 则直接在 gold-defined FC population 上运行，
不再受类型预测是否命中 FC 的串联门控。旧 Phase D 和已揭封 v1 只用于方法选择：

- Phase D 非人类候选上，type coverage 为 `12/100`，选择性一致 `10/12`；在 24 条
  gold-defined FC 中，source head 覆盖 `23/24`，选择性一致 `18/23`。
- v1 严格双 Codex 35 条上，type coverage 为 `5/35`，选择性一致 `5/5`；在 16 条
  gold-defined FC 中，source head 覆盖 `13/16`，选择性一致 `7/13`。

这些值来自 `results/rq3_adjudication/affected_versions_task_separated/`，是明显的
post-hoc、selection-biased、non-human 开发诊断。v1 的类型高选择性一致建立在
`14.29%` 覆盖上，来源头也没有显示稳定优势，因此只能用于冻结 v2 候选，不能作为
论文的确认性性能结果。

## V2 task-separated holdout result

v2 从 651 条 deterministic FC candidates 中排除 Phase D 与 v1 共 200 个 CVE，
在剩余 451 条中冻结 100 条。预测在两个全新 Codex reviewer 之前密封，typing 与
FC-only source 为独立预注册端点。双 reviewer 的 label/artifact 精确一致为
`65/100`、`80/100`，kappa 为 `0.5353/0.6690`；strict type 为 `41/100`，其中
`15 FC`、`8 INC`、`18 RD`。15 条 strict FC 中只有 9 条 strict source consensus，
即全 cohort 的 `9%`。

type primary 只预测 `3/41` 且三条均一致，selective accuracy 为 `1.0`，但
full accuracy `0.0732`，低于 all-FC `15/41` 和 legacy `16/41`。FC-source primary
`branch_release_graph` 为 `2/9`，coverage `5/9`；`prefer_nvd` 为 `6/9`。这不是
方法改进：类型结果是极低覆盖的 selective candidate，来源结果则在仅 9 条非人类
strict source rows 上低于固定 NVD。v2 已揭封，不能继续用于调参后的独立结论；
生产默认保持不变。

## Post-v2 cross-cohort no-go diagnostic

揭封后新增两个受限候选和一个 leave-one-cohort-out 诊断：

```bash
python3 experiments/holdout/analyze_affected_versions_v2_failure_modes.py
python3 experiments/rq3_adjudication/test_affected_versions_authority_graph.py
python3 experiments/rq3_adjudication/test_affected_versions_task_separated_v2.py
python3 experiments/rq3_adjudication/analyze_affected_versions_task_separated_v2_development.py
python3 experiments/rq3_adjudication/test_analyze_affected_versions_leave_one_cohort_out.py
python3 experiments/rq3_adjudication/analyze_affected_versions_leave_one_cohort_out.py
```

`task_separated_type_v2_candidate` 在 Phase D/v1/v2 上分别命中 `7/42`、
`11/35`、`10/41`；authority-filtered source 分别为 `3/20`、`2/16`、
`1/9`。balanced logistic 类型模型的 pooled OOF 为 `70/118`，但留出
Phase D 时为 `22/42`，低于 legacy `27/42`。来源模型 pooled 为 `19/45`，
低于 branch baseline `27/45`。

诊断产物将推进门槛写死为“在每个留出 cohort 上严格多于最佳命名 comparator
的正确数”。类型与来源端点都没有通过者，`advance_to_new_sealed_cohort=false`，
因此当前不冻结 v3。所有输入标签均为非人类、分析方向均为 post-hoc；该结果可用于
拒绝候选和界定实验上限，不能写作确认性方法选择。

产物：

- `results/holdout/affected_versions_v2/posthoc_failure_analysis/`
- `results/rq3_adjudication/affected_versions_task_separated_v2/`
- `results/rq3_adjudication/affected_versions_leave_one_cohort_out/`

## RQ3 human-audit guard

已准备 blank human-audit templates：

- `data/annotations/rq3/gold_audit/severity_adjudication_audit.jsonl`：80 行
- `data/annotations/rq3/gold_audit/affected_versions_adjudication_audit.jsonl`：100 行
- `data/annotations/rq3/gold_audit/sample_manifest.json`

这些文件保留 `silver_v2_annotation` 作为 provenance/context，但人工字段位于
`human_audit`，当前均为 `audit_status=draft`。guarded evaluator：

```bash
python3 experiments/rq3_adjudication/evaluate_rq3_human_audit.py --field severity
python3 experiments/rq3_adjudication/evaluate_rq3_human_audit.py --field affected_versions
```

当前空模板会被拒绝，且不会写出 `*_gold_audit_eval_metrics.*`。只有完成
`audit_status=final`、合法人工标签、证据 URL、annotator/date 等字段后，才能生成
human-audit metrics；`--allow-partial` 也要求至少有一条 final row。

## AI-adjudicated gold diagnostic

The AI-gold pipeline re-reviewed `51/80` severity rows and `96/100`
affected_versions rows. The resulting determinate coverage is `79/80` for
severity and `40/100` for affected_versions; all other rows remain explicit
`final_abstain`.

```bash
python3 experiments/ai_adjudicated_gold/evaluate_rq3_ai_gold.py
```

On determinate AI-gold rows, `evidence_score_baseline` reaches severity accuracy
`0.7215` and macro-F1 `0.7139`. For affected_versions,
`canonical_version_token_support_baseline` reaches accuracy `0.5000` and
macro-F1 `0.2806`; the raw token baseline reaches `0.4750` and `0.2827`.
Because affected_versions gold coverage is only `0.40` and the same model family
contributed candidates and adjudication, these are internal diagnostics rather
than human-gold or final-paper results. No production method is selected.
