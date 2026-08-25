# JSS V3.1 一级评审报告

## 结论先行

- 评审层级：`L1`
- 当前潜力：`P2_VIABLE_CONDITIONAL`，指保守 JSS 研究路线仍可信；不表示当前
  稿件可投或预测接收概率
- 补实验决定：`TARGETED_EXPERIMENTS`，只剩两名真人按冻结 V3.1 执行，不再
  增加字段、第三人、用户实验或同模型 vote
- 当前投稿决定：`NO_GO_FOR_SUBMISSION`
- 一句话理由：强基线、三策略、共享漏判证伪层、双轮校准、回收/锁定/评估代码
  已在真人 exposure 前冻结；但 load-bearing 的可靠性、效率与安全结果仍全部为
  零真人证据
- 下一停止点：作者批准 guideline、两名 reviewer 与伦理/招募记录后，只分发
  calibration-1 action；若需要 calibration-2 且第二轮 action agreement 仍低于
  0.60，则终止正式分发

## 1. 当前评审快照

| 项目 | 当前值 | 核验状态 |
|---|---|---|
| 日期 | 2026-08-25 | `VERIFIED` |
| 权威环境 | `code-defender:/home/xiaoyuliang/code/vuln-adj` | `VERIFIED` |
| 活跃分支 | `codex/jss-v3-1-freeze-20260825` | `VERIFIED` |
| 证据/工具/packet 冻结提交 | `d664f90dce37cfdadd14c399803d7caca8fcf046` | `VERIFIED` |
| 当前协议 | `vuln-adj-jss-t1-human-validation-v3.1` | `VERIFIED` |
| 人工状态 | reviewer 未登记；`human_labels=0`；`distribution_allowed=false` | `VERIFIED` |
| 论文状态 | `S1_EVIDENCE_LOCKED`；manuscript shell；无正文 | `VERIFIED` |

V2 与 V3 均保留为未分发、零真人标签的历史 prepare-only provenance。V3.1 是
唯一允许未来进入分发审批的版本。

## 2. 当前 framing 与 claim ceiling

当前 framing 是：在 CVE-aligned NVD–GHSA 四字段上，用两名独立训练分析员的
maintenance action 作为 reviewer-specific reference，比较 strong field-aware
simple、type-first current 与 type-first abstention 三策略，并显式检验效率端与
人工路由安全端是否能同时成立。

当前允许写入方法/设计的内容：

- 冻结 8,066 行语料上的 status、policy action 和 disagreement 计数；
- V3.1 的 20/20-reserve/120 设计、CVE 互斥、递归 allowlist、hash、stage lock
  和停止规则；
- 34 行 shared-no-manual audit 的存在；
- `delta_manual=0.10` 在零 simple-only loss 时至少需要每名 reviewer 29 个
  human conflict actions；
- 8.43% 是 34 行审计样本的零事件单侧上界，不是总体漏判率。

当前禁止：

- correctness、accuracy、policy superiority、safety noninferiority；
- unnecessary escalation、saved workload、真实维护成本或部署收益；
- 将 synthetic integration fixture、AI/Codex labels 或机械 validator 当真人结果；
- 将 strong simple 称为观察到的行业实践；
- 在任何 reviewer 失败后继续使用 positive efficiency-safety framing。

## 3. 两条结果路线

| 维度 | A：人类支持的 efficiency-safety frontier | B：construct/routing boundary |
|---|---|---|
| 成立条件 | 两名 reviewer 的 formal reliability、效率方向/区间和安全门禁全部通过 | 任一可靠性、方向或安全门禁失败，但失败结构仍可核查 |
| 主证据 | pre-adjudication action；exact McNemar b/c；CVE-blocked CI；reviewer-specific safety bound | disagreement matrix、abstain/uncertain、字段结构、shared miss、门禁失败 |
| 安全要求 | 每人 conflict actions ≥29；type manual coverage 不低于 simple；simple-only loss upper <0.10 | 明确不能排除安全代价，不保留正向 framing |
| 追加实验 | 不追加 | 不追加；失败本身保留 |
| 当前状态 | 人工证据缺失 | 人工证据缺失 |

V3.1 已在结果出现前写死 A 失败自动转 B，因此不存在“看到安全结果后再决定安全
是否必要”的事后口子。

## 4. 主张—证据矩阵

| 主张 | 当前证据 | 状态 | 仍缺什么 |
|---|---|---|---|
| 8,066 行冻结语料和四字段分布可复现 | E01/E07B | `PASS`，snapshot-bounded | 无法外推数据库总体质量 |
| strong simple 与 safety arm 有 2,332 个 action differences | E07B | `PASS`，label-free | 哪个 action 更合理未知 |
| V3.1 盲化、抽样、回收、阶段锁和 evaluator 可机械执行 | E07D/E07E | `PASS`，prepare-only | 不是 human reliability 或性能 |
| 两名 analyst 能稳定使用 action/reason | E08 | `ABSTAIN` | 两名真实独立 reviewer 的完整返回 |
| type-first 在效率端优于 strong simple | E09 | `ABSTAIN` | 两人同方向、exact paired evidence 和区间 |
| type-first 未以人工路由安全为代价 | E09 | `ABSTAIN` | 两人分别通过 29/0.10 安全门禁与 shared audit |
| 当前工作可投稿 JSS | manuscript/venue/artifact/metadata | `FAIL` | 人工结果、正文、格式、元数据和最终 gate |

## 5. Gate 结果

| Gate | 状态 | 依据 | 影响 |
|---|---|---|---|
| L1-G0 权威与快照 | `PASS` | 权威远端、分支、冻结提交、输入 hash 已核对 | 可继续准备 |
| L1-G1 研究问题 | `PASS` | RQs 中性；对象、字段、action、reason 和路由单位固定 | 正/负路线回答同一组 RQ |
| L1-G2 核心 framing | `PASS` | strong comparator、效率臂、安全臂和 fallback 同一协议 | 不再依赖 raw mismatch 稻草人 |
| L1-G3 主张—证据覆盖 | `PARTIAL` | RQ1/设计完整；RQ2/RQ3 真人证据为零 | 不能写正向摘要/结果 |
| L1-G4 贡献可区分性 | `PASS` | differential 限于 action routing、strong baseline、abstention、安全证伪与 no-go | 禁止 first-taxonomy |
| L1-G5 JSS 潜力 | `PARTIAL` | 软件维护决策含义清楚；结果未知 | 当前为条件式 P2 |
| L1-G6 实验充分性 | `PARTIAL` | 协议和代码已冻结；真人未执行 | 只允许最小 human run |
| L1-G7 可写性 | `PARTIAL` | 方法与 RQ1 可写；load-bearing results 空 | 不启动结果驱动全文 |
| L1-G8 停止规则 | `PASS` | 双轮 calibration、0.60/0.40、25/29、0.10、安全失败降级均预注册 | 防止追结果 |

## 6. 最小后续实验

### 实验卡 1：calibration-1

| 字段 | 内容 |
|---|---|
| Claim gap | reviewer 能否在当前 guideline 下理解 action/reason construct |
| 人力 | 两名不同真人，各 20 行；先 action，双人回收锁定后才给 reason |
| 进入门 | guideline、身份/独立性、伦理/招募、精确文件 allowlist 和 author approval |
| 通过 | action raw agreement ≥0.60 且无 material guideline change |
| 条件重试 | 低于 0.60 或 material change 时使用预密封 calibration-2 20 行 |
| 终止 | calibration-2 action raw agreement <0.60；不再发 formal |
| 禁止 | 改 formal case、策略、阈值；复用 calibration；追加第三人 |

### 实验卡 2：formal 120

| 字段 | 内容 |
|---|---|
| Claim gap | RQ2 reliability 与 RQ3 efficiency/safety |
| 人力 | 同两名 reviewer，各 120 行；action 全锁后给 reason |
| 主表 | field × deterministic cell 的人—规则分歧；policy-disagreement paired b/c |
| 安全表 | reviewer-specific conflict count/coverage/loss upper；34 行 shared audit |
| 正向门 | formal raw action ≥0.60、alpha ≥0.40；两人同向效率；两人安全均通过 |
| 失败处置 | 自动转 boundary/ambiguity；不追加样本或第三人 |

## 7. 投稿适配判断

- **JSS：当前最合适的主路线，但仅条件式。** 研究对象是软件维护记录的一致性
  与 routing decision，方法贡献在可复现协议、强基线、公平配对、安全门禁和
  failure boundary；这比纯漏洞检测 accuracy 更贴近 JSS。
- **IST：务实备选。** 若最终结果扎实但贡献体量或叙事长度更适合较紧凑的实证
  系统论文，可使用同一证据包转投；IST 不降低真人与安全门槛。
- **A 类综合 SE 会议/期刊：当前不建议。** 数据源范围、只有两名 analyst、
  缺少真实生产流程与外部/时间验证，使现有课题即使正向也更像扎实 B 档期刊包，
  而不是高上限方法论文。
- **安全专门期刊：不是首选。** 当前中心贡献是维护决策与跨数据库治理，而不是
  新漏洞发现、攻击技术或安全检测性能。

这是 scope/证据匹配判断，不是接受概率预测。JSS 当前作者指南、模板和具体
submission requirements 尚未刷新核对，仍是后期独立 blocker。

## 8. 最终判断

三项最重要的 reviewer challenge 处置为：

1. “两策略会不会一起漏掉不升级案例？”——
   `ANSWERABLE_FROM_FROZEN_EVIDENCE` 仅到设计层：已冻结 34 行证伪层；真人
   shared miss 仍是 `PROPOSE_NEW_EXPERIMENT`，尚未执行。
2. “只证效率、不证安全是否还能正向投稿？”——
   `FATAL_CLAIM_GAP` 对正向 framing；V3.1 已通过 29/0.10 双 reviewer 门禁使
   失败自动收缩为 boundary，不把它降格成普通 limitation。
3. “两名研究组学生能否代表维护实践？”——
   当前是 author-governance blocker。招不到真实从业者时只能使用“trained
   analyst under a fixed rubric”，并把 practitioner relevance 作为 bounded
   limitation；不得通过 reviewer ID 或培训文字虚构从业经验。

当前工作已经从“勉强的 type-first 正向想法”收敛为一个可证伪、能诚实失败的
JSS B 路线。竞争力上限不由更多脚本决定，而由两名真人是否产生：

1. 稳定 construct；
2. 相对 strong simple 的同方向效率信号；以及
3. 不突破 0.10 预注册边界的 reviewer-specific 人工路由安全结果。

因此下一步不是继续扩展自动实验，而是完成 author-owned 分发治理并启动两名
真人的 calibration-1。此前继续保持 `NO_GO_FOR_SUBMISSION` 和
`DISTRIBUTION_BLOCKED`。
