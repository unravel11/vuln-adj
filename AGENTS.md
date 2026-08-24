# Project Agent Rules

本仓库用于承接 `NVD ↔ GHSA` 主线下的字段级漏洞差异检测与证据驱动裁决研究。

## 工作边界

- 先收敛主线：`RQ1 / RQ2 / RQ3`
- 主数据源优先保持为 `NVD ↔ GHSA`
- 当前优先字段为：`severity`、`published/date`、`references`、`affected_versions`，`cwe_ids` 可作为补充字段
- 不把暂未验证的规则、统计或实验现象写成结论

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
