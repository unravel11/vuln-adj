# 漏洞元数据修正、历史回放与下游传播：方向资格审查

**核查日期**：2026-08-31  
**当前结论**：`QUALIFICATION_ONLY`，不是论文方向 `GO`  
**对应协议**：`docs/plans/temporal_provenance_pilot_v1.md`  
**范围**：NVD、CVE List、GHSA 及其 affected-version / fixing-reference
元数据的公开修正、历史状态和下游使用。

## 1. 大白话结论

只做 `affected_versions` 不够。只证明 NVD、GHSA 写得不一样也不够；只证明
数据库后来改过，或者错误会影响统计结果，同样不够。这几条分别已经被 2013
年以来的 affected-version 核验、NVD 数据清洗、跨库差异检测、历史描述补全和
最新的 Java 跨版本 exploit 研究覆盖。

还没有被本轮检索直接覆盖的，是下面这一整条可审计链：先用维护方公开接受的
修正锁定一个 before/after 事件，再按当时可见的数据重放历史状态，随后观察该
修正是否、何时进入其他数据库，并用同一对 before/after 输入运行两个性质不同
的下游消费者。这里的研究对象不是“版本字段”，而是“一个已接受的元数据修正
如何进入公共漏洞数据供应链，以及使用未来状态会怎样改变历史时点的可执行
结果”。

但这只能算候选空白，不能据此写论文。它必须同时通过四个事实门槛：能找到足够
多的公开 accepted correction；历史状态可重放；两个下游任务都有足够的同事件
样本；最接近论文没有已经交付同一任务合同。任何一项不通过，就应该缩题或
`NO_GO`。

## 2. 核查方法与证据边界

本轮围绕六组词检索和回查原始来源：vulnerability database quality / discrepancy，
affected versions，fixing commit references，NVD change history，GHSA review /
accepted contributions，以及 information propagation / temporal evolution。优先使用
出版社页面、会议官方页面、作者全文、开放论文和官方复现仓库；对仅有摘要或
预印本的工作单独标明。仓库中已有的 24 篇全文档案也用于复核，但本文件不是一项
声称检索穷尽性的系统综述。

本文中的“支持”只表示该论文的全文或原始页面直接报告了相应研究对象、方法或
结果。“没有做”只表示在本轮核查的论文和公开 artifact 中没有发现对应任务，
不是断言全世界不存在未检索到的工作。维护方接受或合并一项修正，证明该修正被
采用；它本身不等于独立语义真值。

## 3. 最接近工作的逐篇边界

### 3.1 Nguyen and Massacci：affected version 错误会改变经验结论

Nguyen 与 Massacci 的 *The (Un)Reliability of NVD Vulnerable Versions Data: an
Empirical Experiment on Google Chrome Vulnerabilities*（AsiaCCS 2013，DOI
[`10.1145/2484313.2484377`](https://doi.org/10.1145/2484313.2484377)）已经直接
占据“核验 NVD affected versions 是否可靠”这一基本问题。研究逐版本核验 Google
Chrome 漏洞，发现 NVD 版本数据错误，并比较错误数据与修正数据对 foundational
vulnerability 经验研究结论的影响。

这篇工作意味着，我们不能把“affected-version 元数据可能错”或“错误会让研究
结论变化”写成新贡献。它的范围是单一产品及一次研究分析，不是由维护方 accepted
correction 锚定的多源事件账本，也没有公开记录状态的多时钟 lineage，更没有跨
GHSA / OSV 等消费者的修正传播分析。

### 3.2 Anwar et al.：NVD 多字段清洗和 rectified-data 影响已经做过

Anwar 等人的 *Cleaning the NVD: Comprehensive Quality Assessment,
Improvements, and Analyses*（IEEE TDSC 2022，DOI
[`10.1109/TDSC.2021.3125270`](https://doi.org/10.1109/TDSC.2021.3125270)）是
本方向最强的早期重合项之一。它系统分析 NVD 的发布日期、vendor/product、CVSS
和 CWE 等字段，提出自动修正方法，并用 original 与 rectified NVD 做多项发现、
披露和修复统计案例。论文还报告将结果提交给 NIST 后，NVD schema 删除了论文所
指出的易出问题 free-form vendor/product 名称。

因此，“清洗漏洞数据库并展示对下游分析的影响”也不能作为我们的主要差异。
该工作把同一份 NVD 数据静态修正后重算研究统计；它没有以逐事件的公开接受记录
定义 before/after，没有恢复每一修正的历史可见状态和交易时间，也没有测量修正
进入多个独立数据库或扫描器的传播延迟。它的 downstream 是若干数据分析案例，
不是本协议要求的同事件 SCA alert 与 known-VFC coverage 两类可执行消费者。

### 3.3 Guo et al.：历史描述 before/after 已被用作模型标签

Guo 等人的 *Detecting and Augmenting Missing Key Aspects in Vulnerability
Descriptions*（ACM TOSEM，DOI
[`10.1145/3498537`](https://doi.org/10.1145/3498537)）直接利用 NVD 中修改前后
的漏洞描述：以前一版本为输入，以维护者后来补充的版本构造缺失 aspect 的评估
数据，并研究自动补全 vulnerability type、root cause、attack vector 等文本 aspect。
论文还明确指出公开状态只能保留有限版本，不能恢复所有历史修改。

这篇工作排除了“第一次用漏洞记录的 before/after 更新研究元数据演化”之类的
说法。它研究的是描述文本补全和模型预测，不是 affected range / fixing reference
的 provider-accepted public transaction，也不追踪修正如何进入多个数据库或改变
两个下游消费者。它同时提醒本研究：`lastModified` 与有限的公开前后版本不能自动
当作完整历史，无法恢复的状态必须保留为 unresolved。

### 3.4 Schweigler：漏洞数据库间的静态信息传播图已经存在

Schweigler 的伯尔尼大学学士论文 *An Investigation into Vulnerability Databases*
（2020，[全文](https://scg.unibe.ch/archive/projects/Schw20a.pdf)，
[artifact](https://github.com/Brian6330/VulnerabilityDBInvestigations)）规范化了
CVE、NVD、Exploit-DB、Rapid7 和 Snyk 的 370,298 条记录，并根据重复条目和跨库
引用构造 information-propagation graph。

所以“画出漏洞数据库之间谁引用谁”的静态传播图也不是空白。该论文明确忽略
采集结束后的新发布或更新记录，也没有核验条目的准确性；它不包含 GHSA / OSV，
不区分 correction、backfill、schema migration 和 mirror transaction，更没有
逐事件 adoption delay。因此它覆盖静态来源关系，不覆盖 accepted correction 的
纵向传播。

### 3.5 Sun et al.：跨库 aspect discrepancy 检测已经被系统覆盖

Sun 等人的 *Aspect-level Information Discrepancies across Heterogeneous
Vulnerability Reports: Severity, Types and Detection Methods*（ACM TOSEM 2024，
DOI [`10.1145/3624734`](https://doi.org/10.1145/3624734)）在 NVD、IBM X-Force、
ExploitDB 和 Openwall 中人工标注漏洞 aspect 及 mismatch，并比较多种 NLP 提取和
匹配方法。其研究对象覆盖 vulnerable product/version/component 等七类 aspect，
并区分 absence、overclaim、underclaim 和 total difference。

这项工作意味着“跨漏洞数据库找字段差异”以及“用 NLP 识别差异”都已高度占位。
它对比的是采集到的报告内容，没有 provider-accepted correction oracle，没有固定
检查点的 as-of replay，也没有观察某次修正是否进入下游数据库和工具。

### 3.6 Croft et al.：元数据来源不同会改变下游标签已被证明

Croft 等人的 SANER 2022 工作比较 Firefox 漏洞报告生命周期中的 severity 不一致，
并展示选择不同 severity 来源会改变下游标签和分类结果。它已经占据“源间元数据
差异会影响下游机器学习/分析”的一般主张。

它没有 affected versions 或 fixing references 的同事件真值，也不研究公开修正的
采纳路径。因而我们的差异不能只是“再换两个字段证明下游会变”，必须来自可重放
的 accepted-event lineage 和两种不同消费者。

### 3.7 VFCFinder：找到 fix link 并让 GHSA 接受，已经做过

Dunlap 等人的 *VFCFinder: Pairing Security Advisories and Patches*（AsiaCCS
2024，DOI [`10.1145/3634737.3657007`](https://doi.org/10.1145/3634737.3657007)，
[作者全文](https://enck.org/pubs/dunlap-asiaccs24.pdf)）将 advisory 与候选修复提交
排序。论文报告把 300 多个缺失 VFC 回填到 GHSA 并被接受，形成离线 ranking 与真实
维护采用的闭环。

这篇论文直接占据“自动寻找 fixing commit”“向 GHSA 补 reference”“用 accepted
PR 证明维护价值”。我们不能把同一批 accepted PR 当作独立发现，也不能把模型输出
当作 reference 真值。尚未覆盖的部分是：从 accepted PR 的 before/after 主分支状态
出发，检查该 link 后续是否进入其他数据库，以及在冻结的外部 CVE-to-VFC mapping
上是否改变 coverage。这个差异只有在足够事件可运行时才成立。

### 3.8 Mapping NVD Records to Their VFCs：reference coverage 规模化也已有工作

Nguyen 等人的 *Mapping NVD Records to Their VFCs: How Hard is it?*（截至核查为
[arXiv:2506.09702](https://arxiv.org/abs/2506.09702)）从 NVD references、六个外部
安全数据库和 GitHub 仓库恢复 CVE-to-VFC mapping。摘要报告 NVD 的 Git references
远比 non-Git references 有效，并建立了大规模 mapping；同时指出大部分 NVD 记录
仍无法映射。

这进一步抬高 Task B 的门槛：单纯抽取或补全 VFC link 不新。它可以作为外部映射或
方法基线，但其自动输出不能逐条充当 oracle。我们的 Task B 必须是 accepted change
导致已知 VFC coverage 的配对变化，而不是再次做 mapping 模型。

### 3.9 affected-version 自动识别与 benchmark 已形成拥挤赛道

Bao 等人的 *SZZ for Vulnerability*（ICSE 2022）和后续 VERCATION、ASE 2025
*Vulnerability-Affected Versions Identification: How Far Are We?* 已经系统研究从
修复和提交历史推断受影响版本。ASE 2025 工作构造 1,128 个 C/C++ 漏洞的人工核验
benchmark，并在同一合同上比较 12 个工具；这说明 affected-version identification
本身已经需要强 benchmark 和同任务 baseline。

Chen 等人的 *Assessing the Cross-Version Applicability of Java Library
Vulnerability Exploits*（ASE 2026，DOI
[`10.1145/3832783.3834383`](https://doi.org/10.1145/3832783.3834383)，
[官方页面](https://conf.researchr.org/details/ase-2026/ase-2026-research-track/53/Assessing-the-Cross-Version-Applicability-of-Java-Library-Vulnerability-Exploits)）
更接近当前设想：它建立 259 个 exploit、224 个漏洞、128 个库、28,150 个版本的 Java
数据集，依据 fixing / inducing commits 与 release artifact 源码给版本标注，并把
发现提交给 NVD。

本项目对论文、Zenodo v3 和官方 NVD Change History 做了单独核查。论文报告 19 个
CVE、1,400 多个版本被纳入 NVD Known Affected Software Configurations。公开历史中
可找到 19 个与作者报告时间吻合、带 `CPE Configuration oldValue/newValue` 的更新：
12 个发生在 2025 年 9 月，7 个发生在 2026-04-29。包内列出的另一个
`CVE-2021-29425` 只有作者写的 `Confirmed`，没有对应公开配置变化，当前 NVD 也未
包含作者声称遗漏的旧版本。Zenodo 网页将两批合称 20 个 CVE、1,519 个遗漏版本，
但新增 7 条只写 `partially confirmed by NVD`；公开 after range 也没有覆盖全部声称
遗漏版本。因此，本项目最多称这些为 **19 个与作者报告修正时间吻合、公开可观察的
NVD configuration updates**，不能称 20 个全部 accepted，也不能把 1,519 全部计为
accepted version labels。artifact 没有 GHSA submission、PR、review 或 accepted 记录。

artifact 提供 before CPE JSON 和逐版本 NVD 表，但没有 after snapshot 或独立
`corrections.csv`。精确双状态必须由 artifact before 与 NVD Change History 的
old/new payload 连接构造。按本项目已冻结的发现窗口，只有 2025 年的 12 个更新可作
外部可观察候选；2026-04-29 的 7 个只能留作窗口外验证，不能为增加样本而修改
协议。更重要的是，NVD history 只记录 NVD 的 change event 与 old/new payload，
不公开贡献者或 submission/ticket disposition；论文转述的确认邮件也未作为 artifact
发布。因此这 12 个事件本身仍不满足本项目冻结合同的 public accepted-disposition
条件，只能用于验证 before/after 连接和 Task A，不能计入 50-event 主门槛。

因此，“提出 affected-version 真值”“发现 NVD 遗漏版本”“把证据交给 NVD 并获得
更新”都不是我们的新贡献。可能留下的部分，是在这些已接受更新之后继续追踪 NVD、
GHSA、CVE List / OSV 的状态和延迟，并用更新前后记录运行 SCA；若 artifact 已经提供
完整传播和 scanner 结果，这条差异还会进一步缩小。

### 3.10 Zhang et al.：CVSS 谁先、谁跟随、跟随多久已经被直接覆盖

Zhang、Massacci 与 Zhang 的 *The Cathedral and the Bazaar of Software
Vulnerabilities: From the NVD to the CNAs*（截至核查为
[arXiv:2607.05670](https://arxiv.org/abs/2607.05670)，DOI
[`10.48550/arXiv.2607.05670`](https://doi.org/10.48550/arXiv.2607.05670)）使用
NVD Change History API 与 CVE Program API，重建 44,123 个 CVE 的评分时间线，研究
NVD 与 CNA 的 CVSS divergence、who-first、follow behavior 和 delay。

因此若把本项目写成“比较两个来源谁先改、另一个多久跟随”，会与这篇论文正面
重合。它没有逐事件维护方 accepted-correction oracle，而且论文自己说明一部分
CVSS divergence 可能是合法判断差异；它也没有 affected/reference 两字段、GHSA /
OSV 多消费者和显式 import lineage。我们的时间研究必须锚定可解释的 accepted
correction，而不能把后出现或趋同自动称为纠错。

### 3.11 GHSA review pipeline：审核延迟不是字段修正传播

Segal 等人的 *Characterizing and Modeling the GitHub Security Advisories Review
Pipeline*（MSR 2026，DOI
[`10.1145/3793302.3793360`](https://doi.org/10.1145/3793302.3793360)，
[复现仓库](https://github.com/cmsegal/ghsa-review)）研究 2019--2025 年 GHSA 的 reviewed
状态、审核延迟与 fast/slow path，并给出公开数据和分析代码。

它占据了 GHSA review latency 与流程机制，但 reviewed advisory 不等于某个字段的
修正，也不建立 before/after semantic correction、跨库采用或 scanner output。
我们的 `public_transaction_time`、`provider_record_time` 和
`accepted_disposition_time` 必须分开，不能把 GHSA Git mirror commit time 当作内部
审核时间。

### 3.12 Dong et al.：NVD affected-version 变更历史已经被规模化分析

Dong 等人的 *Towards the Detection of Inconsistencies in Public Security
Vulnerability Reports*（USENIX Security 2019，
[官方全文](https://www.usenix.org/system/files/sec19-dong.pdf)）用 VIEM 从 CVE 描述和
外部报告中抽取产品与版本，并与 NVD 结构化条目比较。其 78,296 个 CVE、70,569 份
报告的主分析已系统覆盖 affected-version overclaim / underclaim。更直接的是，论文
还对 5,000 个版本不一致的 CVE 使用 NVD change history，提取条目创建时间及版本
增加/删除时间，并比较外部报告何时已可见。

因此，“第一次用 NVD change history 研究 vulnerable-version 更新”和“比较版本
信息何时进入 NVD”都不能再写。该工作没有以公开 submission / accepted disposition
锚定更新原因，也没有恢复每次修改的完整 old/new payload、区分同步 lineage，或把
同一修改前后状态送入扫描器。它占据的是大规模不一致与更新时间分析，不是本协议
要求的 accepted-event replay；但它使单纯的时间统计明显不够。

### 3.13 Leung et al.：reference 后增时间和下游工具比较已有强邻近工作

Leung 等人的 *A Data-Driven Automated Approach to Trace Vulnerabilities*
（本轮找到的作者稿仍标为 `Received: date / Accepted: date`，
[全文](https://arcyleung.pages.dev/vul_traceability.pdf)，故不把它写成已确认发表论文）
分析 63 个 CVE 的 NVD change-history events、描述和外部 references。作者稿报告
559 个变更事件中 `Added Reference` 占 71.7%，后加 reference 在 11/63 个漏洞中带来
新的 traceability information；随后以人工 oracle 比较 DICTionary analyzer、Mend
和 Snyk 的组件识别结果。

这不是 provider-accepted correction 研究，也没有逐事件 before/after 重跑在线
工具；其工具比较与 change-history 时间分析也是两个相邻但未绑定的分析。然而它
已经强邻近“reference 后增何时带来新的下游可用信息”。所以本项目不能只报告新增
reference 数量或新信息比例，Task B 必须证明同一个 route-bound accepted event
确实改变冻结外部 CVE-to-VFC consumer 的输出，并明确其发布状态核查边界。

### 3.14 Dietrich et al.：accepted GHSA affected 修正与 SCA 盲点已被连在一起

Dietrich 等人的 *On the Security Blind Spots of Software Composition Analysis*
（SCORED 2024，DOI
[`10.1145/3689944.3696165`](https://doi.org/10.1145/3689944.3696165)，
[作者/机构全文](https://labs.oracle.com/pls/apex/f?p=LABS%3A0%3A11173695178339%3AAPPLICATION_PROCESS%3DGETDOC_INLINE%3A%3A%3ADOC_ID%3A4480)）
检测 Maven 中克隆或 shaded 的脆弱组件，用 PoV 验证暴露，并比较 Grype、
OWASP Dependency-Check、Snyk 和 Steady 的漏报。论文报告由结果产生的 10 个 GHSA
修改通过 accepted PR 落地；它还明确说明 GHSA 随后演化会使依赖数据库的 SCA 工具
报告更多这些组件，从而影响复现实验结果。

这是当前最危险的重合项。它已经把“可执行暴露证据 → GHSA accepted affected-data
修改 → SCA 结果将随数据库更新改变”连了起来。因此本项目不能把“accepted GHSA
修正会影响 scanner”写成贡献。该论文没有枚举一个冻结时间窗内的全部修正，也没有
为每个 PR 恢复 proposal/main before/after、量化跨源传播延迟，或用同一配对状态
实际重跑两个性质不同的消费者。若本项目最后只做 affected 字段和一个 scanner，
即使样本更多，也应视为与该工作增量不足；保留路线必须依靠系统事件账本、as-of
replay、lineage 和 reference consumer 的联合结果。

### 3.15 Mohayeji et al.：GHSA 驱动 Dependabot 的可执行下游已被大规模研究

Mohayeji 等人的 *Investigating the Resolution of Vulnerable Dependencies with
Dependabot Security Updates*（MSR 2023，DOI
[`10.1109/MSR59073.2023.00042`](https://doi.org/10.1109/MSR59073.2023.00042)，
[正式论文页面](https://research.tue.nl/en/publications/investigating-the-resolution-of-vulnerable-dependencies-with-depe/)）
研究 JavaScript 项目如何接收和处理 Dependabot security updates。方法使用 2021-03-27
取得的 1,063 条 GHSA 记录，把 2019--2020 年 Dependabot PR 的 parent / merge commit
分别作为有漏洞与已修复的项目状态，并运行版本范围匹配；论文还指出 dependency
files 或 GHSA 数据变化会触发 Dependabot 重扫，且在合并态发现 133 个仍未清除 alert
的案例，随后复现实为 Dependabot 处理多范围时的 bug。

更重要的是，Agaronian 的 2021 年前身硕士论文
[*On Resolution of Vulnerable Dependencies with Dependabot Security Updates in
JavaScript Projects*](https://research.tue.nl/en/studentTheses/on-resolution-of-vulnerable-dependencies-with-dependabot-security/)
记录了更完整的方法：当前 GHSA snapshot 无法解释 479 个历史 update 后，作者从旧
commit、Dependabot/Renovate PR、讨论和 NVD 中人工恢复 8 个被修改、撤下或重发的
package advisory；附录为 `ws`、`kind-of` 等范围变化建立修改日期前后的时间特例，
再将无法关联的 update 降到 28（0.6%）。因此，“第一次发现 current GHSA 不能直接
解释过去”以及“第一次用下游 update 痕迹恢复旧 affected range”也已有直接先例。

这项工作仍不是 provider-accepted correction 的全量研究：它从 downstream traces
为特定分析补回少数历史 records，没有枚举公开 accepted PR，没有绑定 proposal 与
main adoption delta，没有跨数据库 lineage，也没有第二个 reference consumer。它
一方面占据“GHSA 范围驱动真实 dependency alert / update”的下游合同，另一方面把
本项目门槛提高为：必须做系统、route-bound、可机械复核的 as-of replay，并与
current-snapshot replay 配对比较；只再跑一次通用 scanner，或只展示几个手工恢复
案例，贡献不足。

## 4. 横向比较矩阵

符号含义：`是` 表示论文直接交付；`部分` 表示只覆盖邻近构件；`否` 表示本轮核查
未发现该任务。矩阵只用于定位重合，不是给论文质量打分。

| 工作 | affected / reference 字段 | 真实 before/after 状态 | 公开 accepted disposition | 历史 as-of replay | 跨数据库传播/延迟 | 可执行下游影响 | 公开 artifact |
|---|---:|---:|---:|---:|---:|---:|---:|
| Nguyen & Massacci 2013 | affected | 部分 | 否 | 否 | 否 | 研究统计 | 部分 |
| Cleaning the NVD | affected 邻近、多字段 | rectified pair | 部分（schema 响应） | 否 | 否 | 多项统计分析 | 是 |
| Missing Key Aspects | 描述 aspect | 是（有限历史） | NVD 更新作标签 | 部分 | 否 | 模型预测 | 未复核 |
| Bern 2020 | 多源记录 | 否 | 否 | 否 | 静态引用图 | 否 | 是 |
| Aspect-level Discrepancies | version 等文本 aspect | 否 | 否 | 否 | 横截面差异 | 检索门户/用户研究 | 是 |
| Croft SANER 2022 | severity | 生命周期状态 | 否 | 部分 | 单项目/来源链 | 标签/分类结果 | 是 |
| VFCFinder | references | GHSA contribution pair | 是 | 否 | 否 | GHSA 采用 | 是 |
| Mapping NVD to VFCs | references | 否 | 否 | 否 | 多源补全 | mapping coverage | 数据许可待核 |
| ASE 2025 affected benchmark | affected | 代码/版本历史 | 否 | 代码历史，不是数据库 replay | 否 | 工具 benchmark | 是 |
| ASE 2026 cross-version exploits | affected | before artifact + 19 个公开 NVD old/new | 19 个时间吻合更新；无 GHSA accepted | 部分 | 未发现 | exploit applicability / DB accuracy | 是 |
| Cathedral/Bazaar | CVSS | 是 | 否 | 评分 timeline | NVD--CNA follow delay | 否 | 未复核 |
| GHSA review pipeline | advisory review | review timestamps | reviewed disposition | 否 | NVD-first / GRA path | 否 | 是 |
| Dong et al. USENIX 2019 | affected | change-history version updates | 否 | 部分 | NVD 与外部报告时间 | 否 | 未复核 |
| Leung et al. author manuscript | references/traceability | change-history events | 否 | 部分 | reference 后增时间 | DICTionary/Mend/Snyk 横截面 | 未复核 |
| Dietrich et al. SCORED 2024 | affected/shaded packages | GHSA contribution pair | 是 | 否 | 仅预期数据库同步 | 多个 SCA + PoV | 是 |
| Agaronian 2021 / Mohayeji et al. MSR 2023 | affected | 项目 parent/merge；8 个包的旧 advisory 恢复 | 否 | 部分（downstream traces） | GHSA 驱动 Dependabot | alert/update lifecycle | thesis 是 |
| 本协议候选合同 | affected + references | 必须 | 必须 | 必须 | 必须 | SCA + known-VFC 两任务 | 必须 |

## 5. 文献真正留下的差异，以及不能再写的贡献

不能再写的贡献包括：首次发现漏洞数据库不一致；首次发现 affected versions 有错；
首次证明脏数据改变经验研究结果；首次研究漏洞记录更新；首次画数据库信息传播图；
首次计算 NVD 与上游谁先更新；首次自动寻找 fixing commits；首次向 GHSA 或 NVD
提交版本/reference 修正；首次说明 accepted GHSA affected-data 修改会改变 SCA
可见性。这些说法分别被上述工作直接或强邻近覆盖。

当前只剩一个组合式、而且风险很高的差异：**以公开 accepted correction 为事件
锚点，恢复修正前后在各来源当时可见的状态，显式保存交易时间、记录时间和观察
时间，区分复制/导入 lineage 与独立采用，再把同一对状态送入 affected-range SCA
和 known-fixing-reference coverage 两个消费者。** 新意若存在，主要在 event ledger、
as-of replay 和 multi-consumer propagation 的同一任务合同，而不在任何单个字段或
扫描器。

这仍然可能不够。组合现有构件只有在它揭示一个过去研究无法回答、并且有足够样本
支撑的现象时才有贡献。例如，它可以回答：维护方已经接受的修正，在其他公共源中
有多少仍长期不可见；采用延迟是不是来源同步 lineage 的结果；用今天的数据重跑
历史实验会改变多少实际 alert / fix coverage。若最后只有几个案例、一个字段或一类
输出变化，这个组合不应包装成广泛新方向。

## 6. 由文献反推的实验设计

### 6.1 E0：先证明历史状态能被机械重放

从冻结的、只用于选 ID 的当前 NVD--reviewed-GHSA 交集里，以与结果无关的哈希顺序
选择 100 个 CVE。在 2024-01-01、2025-01-01 和 2026-05-31 三个固定检查点，从固定
Git commit / API 观察恢复原始 bytes，再运行同一 normalizer。当前状态必须与官方
来源达到协议中的 replay gate；失败表示工程基础不足，不是“数据库存在显著漂移”。

这一阶段特别回应 Guo 等人指出的有限历史问题，以及 NVD 2026 schema / change-
history payload 变化。CVE List 是 CNA/ADP source，不得伪装成历史 NVD；FKIE Git
镜像是社区重建，不得写成 NIST 官方 version store；GHSA Git commit 是公开镜像
transaction，不得替代内部 curator time。

### 6.2 E1：枚举 accepted corrections，而不是挑有趣差异

在预先冻结的 2024-01-01 至 2025-12-31 期间，枚举公开 merged PR、NVD 明确处理的
correction 或具有同等可审计 disposition 的事件。每个 CVE、字段、disposition
生成候选；先机械套用 event contract，再看 effect。bulk sync、schema migration、
backfill、path migration、mirror rollback 和 timestamp-only rewrite 单独标记，不能
混入自然修正主分析。

这里的计数单位必须同时报告 event 和 CVE cluster。accepted 只给出 adoption label；
若要声称 correction 的事实正确性，还需独立的 fix commit / release artifact / vendor
advisory 等证据，并允许 unresolved。

### 6.3 E2-A：affected range 的下游效果

把同一 accepted event 的 before/after package-range 投影成两份冻结 OSV record，
在同一 package-version universe 上运行同一 pinned offline OSV-Scanner。输出是 alert
集合增删，而不是笼统的“准确率提升”。若与 ASE 2025/2026 benchmark 有同 CVE、
同 ecosystem、同 version unit 的交集，可作为独立验证子集；没有 exact overlap 时
不能把 scanner 输出当真值。

文献带来的强制门槛是：Task A 不能只展示 NVD 与 GHSA 当前 snapshot 的差异；必须
来自 accepted before/after event。若少于 50 个可执行事件或变化几乎都由单次 bulk
事件产生，广义 affected route 停止。

### 6.4 E2-B：fixing reference 的下游效果

在同一 URL identity contract 下提取 before/after direct commit、PR 和 patch link，
用版本化的外部 CVE-to-VFC mapping 判断 known VFC 是否被覆盖。人工映射可以作为
oracle 子集；自动 mapping 和 VFCFinder 排名只能作为 baseline。必须报告
eligible、mapped、source-discriminating 和 changed-output 四层分母。

VFCFinder 已经完成“大量 accepted GHSA link contribution”，所以 Task B 只有在研究
这些 contribution 的后续传播或独立事件集时才不是重复。若人审 mapping 与项目
事件交集太小，或 before/after 对 known-VFC coverage 没有足够判别样本，应按协议
将 Task B 判为 `NO_GO`，不能换成几个成功故事。

### 6.5 E3：传播不是简单的“另一个库后来也一样了”

每个事件至少记录 source record、public transaction、accepted disposition 和本研究
observation 四类时间；对每个下游状态记录 first-observed commit/API event。若下游
直接导入上游，变化是 pipeline synchronization，不是独立确认；若两者来自同一
CVE List payload，也不能当作两个独立采用者。主结果应分别报告直接 lineage、疑似
共享上游、独立来源和 unknown，不得合并成一个传播率。

### 6.6 统计与结论

先给 discovery、eligible、replayable、executable 四层分母，再给 paired transition；
按 CVE 聚类 bootstrap 区间，只在 denominator 足够时使用。E0 是资格实验，不做为了
显著性而调窗口或换检查点。即使两个任务都出现变化，最多得到
`GO_FOR_CONFIRMATORY_DESIGN`；它不等于方法正确、数据库不可靠、论文可投或会被
接收。

## 7. 当前判定

文献审查后的判断不是“推荐立刻写”，而是：**允许继续跑一个有硬停止门的资格
pilot。** 方向的最低完整贡献不再是 affected versions，而是 accepted-correction
event ledger + historical replay + explicit lineage + two downstream consumers。

最可能的失败点有三个。第一，NVD accepted correction 的公开逐事件证据不够，或
无法恢复修正前 payload。第二，affected 与 reference 两字段各 50 个事件的门槛过不
去。第三，两个外部 benchmark / mapping 与事件交集太小，只剩工程案例。任一出现，
应及时 `PARTIAL` 或 `NO_GO`，而不是先写文章再补叙事。

## 8. 主要来源

- Nguyen and Massacci, AsiaCCS 2013:
  https://arxiv.org/abs/1302.4133
- Anwar et al., IEEE TDSC:
  https://faculty.cc.gatech.edu/~frankli/papers/nvd_tdsc2022.pdf
- Guo et al., ACM TOSEM:
  https://doi.org/10.1145/3498537
- Schweigler, University of Bern:
  https://scg.unibe.ch/archive/projects/Schw20a.pdf
- Sun et al., ACM TOSEM:
  https://doi.org/10.1145/3624734
- Dunlap et al., AsiaCCS 2024:
  https://enck.org/pubs/dunlap-asiaccs24.pdf
- Nguyen et al., CVE-to-VFC mapping:
  https://arxiv.org/abs/2506.09702
- ASE 2026 cross-version exploit applicability:
  https://doi.org/10.1145/3832783.3834383
- ASE 2026 replication package, Zenodo v3:
  https://zenodo.org/records/21702313
- Zhang et al., NVD--CNA CVSS evolution:
  https://arxiv.org/abs/2607.05670
- Segal et al., GHSA review pipeline artifact:
  https://github.com/cmsegal/ghsa-review
- Dong et al., USENIX Security 2019:
  https://www.usenix.org/system/files/sec19-dong.pdf
- Leung et al., author manuscript (publication status unconfirmed):
  https://arcyleung.pages.dev/vul_traceability.pdf
- Dietrich et al., SCORED 2024:
  https://doi.org/10.1145/3689944.3696165
- Mohayeji et al., MSR 2023:
  https://doi.org/10.1109/MSR59073.2023.00042
- Agaronian, TU/e master thesis 2021:
  https://research.tue.nl/en/studentTheses/on-resolution-of-vulnerable-dependencies-with-dependabot-security/
- NIST NVD technical updates:
  https://www.nist.gov/itl/nvd
- GitHub Advisory Database contribution contract:
  https://github.com/github/advisory-database/blob/main/README.md

这些来源支持各自报告的任务和边界，不支持本项目的 novelty、事件数量、下游效果
或投稿可行性；后四项只能由冻结实验与更完整的 closest-work audit 决定。
