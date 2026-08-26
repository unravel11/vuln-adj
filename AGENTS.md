# Project Agent Rules

本仓库用于承接 `NVD ↔ GHSA` 主线下的字段级漏洞差异检测与证据驱动裁决研究。

## 工作边界

- 先收敛主线：`RQ1 / RQ2 / RQ3`
- 主数据源优先保持为 `NVD ↔ GHSA`
- 当前优先字段为：`severity`、`published/date`、`references`、`affected_versions`，`cwe_ids` 可作为补充字段
- 不把暂未验证的规则、统计或实验现象写成结论

## 论文写作语气：证据校准，不做防御式写作

- 写作目标是让表述强度与证据强度准确匹配，不以“尽量保守”为默认；不得用密集限定、反复免责声明或自我辩护代替清楚论证。
- 对材料直接报告的观察、数值、比较和已执行动作使用直接陈述；对结果解释只使用一个最准确的限定，如 `suggests`、`is consistent with` 或 `may`；未验证内容明确标为 hypothesis、possibility 或 future work。
- 不得在同一命题上叠加同义认识性限定，如 `may perhaps`、`might possibly`、`appears to suggest that it may` 及等价中文。若多个限定约束不同维度，必须明确区分其作用，不能堆叠成笼统退缩。
- 不使用 `to the best of our knowledge`、`we believe`、`it should be noted`、`we cautiously argue`、`we do not intend to claim` 等作者心理或预防审稿式元话语。直接写实际命题，并把真实范围条件放在命题本身。
- 适用范围在首次影响结论的位置说明；系统性局限集中到 Threats to Validity 或 Limitations。只有具体结论依赖该边界时才局部重申，不在每段重复。
- 贡献段按 problem -> gap -> action -> observed result 组织；不得在贡献句中预先写道歉、免责声明或 reviewer rebuttal。
- 去除防御式外壳绝不授权加强主张：不得把相关性改成因果、局部结果改成普遍结论、实验支持改成证明，或把候选/结构证据改成漏洞/真实影响；不得添加 novelty、SOTA、有效性、部署或投稿就绪主张。
- 改写前后核对数字、否定、模态、因果强度、比较基线、范围、引用和术语，只做最小修改；不确定时保留或在正文外标注，不得猜测。

## 执行要求

- 开始前先确认任务属于哪个阶段；如果不在总计划里，先补计划再执行
- 本项目权威执行环境为 `xiaoyuliang@100.101.249.5:/home/xiaoyuliang/code/vuln-adj`，远端主机名应为 `code-defender`
- 从本地进入远端时，优先使用 Codex skill：`ssh-vuln-adj`；已在远端时直接在上述项目目录执行
- 除非用户明确要求只改本地文件，代码运行、数据处理、实验脚本、依赖安装和会产生结果文件的命令都应在上述远端项目目录执行
- 产生结果前用 `hostname` 与 `pwd` 核对远端环境；若连接、主机名或路径不匹配，先明确说明阻塞点，不要把其他环境的运行结果当作权威远端验证结果
- 代码改动优先局部、可验证、最小必要修改
- 不因为顺手方便而重构已跑通的数据链路
- 不能把假设、猜测或未复现实验结果写进文档

## 计划与进度维护

- 总计划维护在 `docs/plans/project_master_plan.md`
- 进度日志维护在 `docs/plans/project_progress_log.md`
- 每完成一个有明确产物的阶段性子任务，必须同步更新进度日志
- 若阶段状态发生变化，也必须同步更新总计划中的状态

## 进度日志最少要写清楚

- 日期
- 本次完成了什么
- 产物路径
- 如何验证
- 当前观察到的效果或统计
- 还没验证的点
- 下一步

## 完成判定

- 只有在文件已落盘、脚本已运行或结果已可核查时，才能写“完成”
- 如果只是实现了代码但未运行验证，只能写“已实现，未验证”
- 如果规则明显只是 baseline，必须显式标注为 baseline，不能写成最终方法

## 大模型调用配置

- 本项目本地环境变量写在仓库根目录 `.env` 中；该文件包含密钥，必须保持为本地文件，不要提交到版本库。
- 调用 OpenAI 兼容接口时，从环境变量读取：
  - `OPENAI_BASE_URL`
  - `OPENAI_API_KEY`
  - `OPENAI_MODEL`
- 当前接口按 OpenAI 兼容格式调用，`base_url` 需要包含 `/v1`，模型名使用 `gpt-5.5`。
- 若使用 SDK，需确保当前 Python 环境已安装 `openai` 包。Python SDK 调用示例：

```python
import os

from openai import OpenAI

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url=os.environ["OPENAI_BASE_URL"],
)

response = client.chat.completions.create(
    model=os.environ.get("OPENAI_MODEL", "gpt-5.5"),
    messages=[
        {"role": "user", "content": "Reply with exactly: pong"},
    ],
    temperature=0,
    max_tokens=16,
)

print(response.choices[0].message.content)
```

- 若脚本没有自动加载 `.env`，先在 shell 中执行 `set -a; source .env; set +a`，或在 Python 脚本中使用项目已有的 dotenv 加载方式；没有依赖时不要为一次性调用强行引入新依赖。
