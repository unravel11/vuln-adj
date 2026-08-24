# JSS V3 一级评审报告

## 结论先行

- 评审层级：`L1`
- 当前潜力：`P2_VIABLE_CONDITIONAL`，仅指研究方案在保守主张下存在可信
  JSS 路径；当前稿件与证据仍不可投稿
- 补实验决定：`TARGETED_EXPERIMENTS`
- 一句话理由：全语料零人工普查已证明强基线、效率臂和安全臂存在可识别的动作
  差异，并暴露出 conflict queue 与总人工路由方向相反；只需一轮冻结的双真人
  action-first/reason-second 实验即可决定正向 frontier 或负向 ambiguity framing，
  但当前真人证据为零
- 下一停止点：冻结 return/evaluator 与分发治理后，完成 20 行 calibration；若
  calibration action 原始一致性低于 0.60，停止正式分发并只做 outcome-independent
  guideline 修订

## 1. 当前评审快照

| 项目 | 当前值 | 核验状态 |
|---|---|---|
| 日期 | 2026-08-25 | `VERIFIED` |
| 论文基线/路径 | `paper/jss/`，历史 `paper/cose/` 仅作证据来源 | `VERIFIED` |
| 仓库、分支、HEAD | `code-defender:/home/xiaoyuliang/code/vuln-adj`；`codex/jss-v3-routing-precheck-20260825`；任务起点 `5a0238750600e9eef78d3eb39c3d3810df5cd1d7` | `VERIFIED` |
| 实验版本 | routing precheck V1；human protocol/packet V3 | `VERIFIED` |
| 工作树/推送状态 | 本报告生成时为受控未提交变更；最终 clean/commit 需在交付复核；未 push | `PARTIAL` |
| 与上次评审的关系 | 取代 V2 的 50/250 taxonomy-only 主动路线；V2 保留未分发历史记录 | `VERIFIED` |

## 2. 当前 framing 与 claim ceiling

- 当前 framing：在 CVE-aligned NVD–GHSA 四字段上，比较强字段简单策略、
  type-first 当前效率臂和加入 abstention 的安全臂；由两位独立训练分析员先给
  maintenance action，再给 discrepancy reason，检验效率—安全 frontier。
- 允许的核心主张：冻结语料上的 status/policy-output/disagreement 计数；V3
  设计、可识别性容量和 prepare-only 状态；若真人门禁通过，再报告 reviewer-
  specific 的配对 action alignment、abstention、conflict escalation 和不确定性。
- 明确禁止的升级主张：无真人前的 correctness、accuracy、superiority、safety、
  unnecessary escalation、workload reduction、部署收益和 submission readiness；
  不得把 strong simple 称为真实行业实践。
- 最关键的 load-bearing claim：至少一个 type-first 臂在两位独立 reviewer 上都
  形成同方向、可区分于强字段基线的 action alignment，同时 construct reliability
  未触发停止门禁。

## 3. Framing A/B 潜力门

| 维度 | Framing A：人类支持的效率—安全 routing frontier | Framing B：action construct ambiguity 与字段边界审计 |
|---|---|---|
| 一句话定义 | 三条冻结策略在独立真人 action 上形成可报告的效率与安全取舍 | 当人类不能稳定或一致地把字段差异映射到动作时，报告这种不可识别性及其字段结构 |
| 直接证据 | E07B 已有 2,332 个主策略 action differences 和固定抽样容量；E07C packet 已冻结 | E07B 已显示信号集中于 affected versions、published 无策略差异，且旧 E04–E06 有大量拒判/失败证据 |
| JSS 价值 | 提供可复用的 field-aware comparator、action vocabulary、abstention accounting 和人类评测协议 | 提供决策构念、字段可比性和自动 reconciliation 失败边界的实证方法论 |
| 最大缺口 | E08/E09 真人动作、可靠性与配对结果全部缺失 | 仍需真人负结果，不能从 deterministic disagreement 直接推断 construct ambiguity |
| 所需新增工作 | 同一轮 2×120 正式 action/reason，外加预冻结 evaluator | 同一轮 V3；若门禁失败，不追加样本寻找正结果 |
| 潜力档位 | `P2_VIABLE_CONDITIONAL` | 当前 `P1`，获得清楚且跨字段的真人 ambiguity 结构后可到 `P2` |

判定：`A` 作为条件式主路线，`B` 作为同一冻结实验的结果独立 fallback。A 失败时
不得另换样本修补，应按预先定义转入 B 或 no-go。

## 4. 主张—证据矩阵

| 论文主张 | 当前证据与路径 | 证据身份 | 支撑状态 | 可用表述 | 缺口 |
|---|---|---|---|---|---|
| 冻结语料有 8,066 行、32,264 个 V3 field instances | `data/processed/bootstrap/discrepancies/nvd_ghsa_field_views.jsonl` | 当前确定性输入 | `PASS` | “在冻结语料与管线下” | 不能外推数据库总体质量 |
| 三主策略存在实质 action disagreement | `results/jss/t1_routing_precheck_v1/analysis.json` | label-free census | `PASS` | simple 与 safety arm 差 2,332 个动作 | 哪个动作正确未知 |
| safety arm 降 conflict queue 但升 total manual route | 同上 | deterministic policy output | `PASS` | `-74` conflict、`+950` conflict+abstain | 不能称成本、安全或效用 |
| V3 能以低人工量覆盖关键差异 | V3 protocol、manifest 和 20 个正式 sampling cells | outcome-independent design | `PASS` | 120 formal cases 具有最多 110 个 action-disagreement capacity | capacity 不是 realized power/effect |
| 两位真人能稳定给 action/reason | E08 | 缺失真人证据 | `ABSTAIN` | 只能写 protocol/hypothesis | reviewer、返回和一致性均不存在 |
| type-first 胜过 strong simple | E09 | 缺失真人配对结果 | `ABSTAIN` | 不得正向表述 | 两位 reviewer 同方向与 CI 门禁未检验 |
| 当前工作可投稿 JSS | manuscript、venue、artifact、metadata gates | 不完整 | `FAIL` | `NO_GO_FOR_SUBMISSION` | 正文、人类证据、格式和元数据均缺 |

## 5. Gate 结果

| Gate | 状态 | 依据 | 对论文的影响 |
|---|---|---|---|
| L1-G0 权威与快照 | `PARTIAL` | 权威远端、分支、输入 hash 与历史 V2 已区分；本报告生成时待最终 commit/clean 复核且未 push | 可继续准备，不能声称已合并或远端公开 |
| L1-G1 研究问题 | `PASS` | 对象、四字段、field instance、action、reason、conflict 与 abstain 单位已冻结 | 问题属于经验软件工程与维护决策评测 |
| L1-G2 核心 framing | `PASS` | 强基线与效率/安全臂同一 estimand；workload 主张已降级 | 可形成一致的候选论证 |
| L1-G3 主张—证据覆盖 | `PARTIAL` | RQ1 和设计证据完整；RQ2/RQ3 load-bearing human evidence 缺失 | 当前只能评研究方案，不能写正向摘要 |
| L1-G4 贡献可区分性 | `PASS` | closest work 已覆盖差异类型；当前 differential 限定为 strong-comparator action routing、stage lock 与 no-go | 禁止 first-taxonomy 表述 |
| L1-G5 JSS 潜力 | `PARTIAL` | frontier/ambiguity 均有软件维护含义，但尚无真人结果 | 研究方案 P2，当前证据包非 P2 成稿 |
| L1-G6 实验充分性 | `PARTIAL` | 公平主对照、抽样 cells、权重、停止规则已冻结；return/evaluator 和 human run 缺失 | 只允许最小 targeted experiment |
| L1-G7 可写性 | `PARTIAL` | 问题—方法—确定性 census 可写；核心结果章节为空 | 暂不开始结果驱动的全文承诺 |
| L1-G8 停止规则 | `PASS` | calibration/evaluation reliability、conflict count、reviewer direction 与 systematic-failure 阈值已预先写死 | 可防止追显著性和换样本救 framing |

## 6. 是否继续补实验

- 主决策：`TARGETED_EXPERIMENTS`
- 为什么：A framing 有明确 P2 路径；剩余工作直接填 load-bearing human gap，
  设计已冻结，正/负/无差异都有预定论文处置，且无需扩大字段或另做用户实验。
- 不需要做的实验：用户研究、第三位常规 reviewer、四字段平均加样、CWE 加入
  V3、额外 LLM vote、再建 raw mismatch baseline、未满足双边资格的时间 cohort、
  为已有 affected-version 机制继续做 post-hoc case patch。

### 实验卡 1：冻结 V3 返回与分析实现

| 字段 | 内容 |
|---|---|
| Claim gap | 保证 E08/E09 的计算口径在真人 exposure 前固定 |
| Minimal design | action/reason return schema、stage lock、completion、nominal alpha、paired match、CVE-blocked CI、cross-reviewer association、adjudication-exclusion sensitivity |
| Independence | evaluator 不读取期望方向；独立 validator 重算 packet/return/hash/cell；负例必须 fail closed |
| Positive action | 允许在分发批准后开始 calibration |
| Negative action | validator/evaluator 无法冻结则不分发，不用手工表格替代 |
| Stop rule | 所有预定 endpoint、threshold 和 negative tests 通过即停止实现，不新增探索指标作为主结果 |
| Claim ceiling | 实现和机械通过仍不是 human evidence 或 submission readiness |

### 实验卡 2：V3 双真人 action-first/reason-second

| 字段 | 内容 |
|---|---|
| Claim gap | RQ2 construct reliability 与 RQ3 三策略 action alignment |
| Minimal design | 两位不同真人；20 calibration + 同一 120 formal；action 全部锁定后 reason；pre-adjudication primary；formal 50/50/10/10 |
| Independence | policy-blinded packet、不同顺序、sealed mapping、author policy-blinded adjudication、hash manifest |
| Positive action | 两位 reviewer 同方向且可靠性/CI 过门时写 frontier paper |
| Negative action | reliability 失败转 decision ambiguity；策略方向冲突或无差异则停止正向 superiority 主张 |
| Stop rule | calibration raw action agreement <0.60 阻断 formal；formal raw <0.60 或 alpha <0.40 禁止正向 routing；不扩样救结果 |
| Claim ceiling | 不测 elapsed labor、deployment、source truth、行业采用或未来快照泛化 |

## 7. 结果处置

| 结果/表格/分析 | 处置 | 理由 |
|---|---|---|
| 8,066-row deterministic status census | `正文` | RQ1 直接证据，需保持 snapshot ceiling |
| 七策略全量输出与 pairwise disagreement | `正文/附录` | 三主臂进正文，raw/canonical/always/abstain-all 完整表入附录 |
| conflict `-74`、total manual `+950` | `正文` | 建立 frontier 必需，但必须标 policy output |
| V2 50/250 packet | `历史` | 零真人、未分发、非当前低人工路线 |
| V3 20/120 blank packet | `方法/复现包` | 证明冻结设计，不是结果 |
| 旧 same-model AI candidate 指标 | `附录/历史` | 仅作 failure/protocol provenance，不能替代 E08/E09 |
| 受揭封 outcome 影响的 affected-version mechanism diagnostics | `降级/附录` | 可解释失败，不可作主方法增益 |
| 未来未满足资格的 temporal claim | `禁止` | 双边 post-freeze cohort 不存在 |

## 8. 已验证、推断与未验证

### 已验证事实

- 权威输入为 8,066 行，V3 四字段共 32,264 个实例。
- full-corpus analyzer 与独立 verifier 对主比较 2,332 个 action differences 和
  conditional Go 一致。
- V3 blank packet 为 20 calibration、120 formal，normal validator 通过，强制
  distribution-ready gate 拒绝，真人标签为 0。
- safety arm 相对 simple 的 deterministic conflict queue 为 `-74`，total manual
  route 为 `+950`。

### 评审推断

- 强基线把“赢 raw non-equal 稻草人”的风险降下来了，frontier framing 比单向
  workload-reduction framing 更可信。
- 若 V3 得到稳定、同方向的真人结果，研究方案有 P2 JSS 路径；这不是接收概率预测。
- affected_versions 将承担大部分可区分信号，published 的角色主要是 construct
  control，因此正文必须按字段解释，不能四字段平均包装。

### 未验证或缺失材料

- 两位 reviewer 的真人身份、资格、独立性、是否为 practitioner、伦理/招募与补偿。
- 任一 action/reason label、agreement、alpha、policy match、conflict recall 或
  adjudication sensitivity。
- return/evaluator 实现、完整 JSS 正文、当前 venue requirements、作者 metadata、
  final artifact 和 push/merge 状态。

## 9. 下一步

1. 完成实验卡 1，并重新调用 `L1+L2` 只审 V3 protocol/evaluator readiness。
2. 作者批准 guideline、reviewer 与伦理/招募记录后，创建独立 distribution
   revision；不得直接翻转当前 prepare-only manifest。
3. 完成 calibration 并应用冻结 gate；只有通过才执行 formal 120。
4. 两份 formal reason 返回冻结后重新调用 `L2`，决定 E08/E09 是否足以进入正文；
   完整稿形成后再调用 `L3`。
