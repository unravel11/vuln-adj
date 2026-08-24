# Repository hygiene record

本目录记录 2026-08-24 对权威远端仓库的保守整理。目标是让 Git 只承载可审查的
源码、协议、文档和小型控制文件，同时保留但不误提交大体积数据、外部证据和历史
生成结果。仓库整洁不代表实验有效、human-gold 完成或论文可投稿。

## 整理前基线

- 权威环境：`code-defender:/home/xiaoyuliang/code/vuln-adj`
- 基线提交：`659831571df7d4b0a3ae6549afd0fc8dae5a6927`
- 整理分支：`codex/repo-hygiene-20260824`
- 工作目录：约 `2.3G`
- tracked 改动：`21` 个路径
- 未跟踪文件：`4,399` 个，其中约 `229 MB`
- 主要未跟踪 payload：`data/evidence_cache` 约 `129 MB`，历史
  `data/annotations` 约 `98 MB`

## 分类策略

| 类型 | 处理 |
|---|---|
| 源码、测试、协议、prompt、论文源文件 | 纳入分步 Git 提交 |
| README、manifest、sealed control metadata | 小文件纳入 Git；不能据此声称语义有效 |
| raw/processed 数据、results、外部 PDF、evidence cache、历史生成 payload | 保留在权威机器，精确忽略，并由哈希清单绑定 |
| `.env`、本地 agent 设置、`.venv` | 保留本地且忽略；不得提交密钥或机器配置 |
| `__pycache__`、`*.pyc`、`.DS_Store`、误生成命令片段 | 明确删除；均为可再生或无意义文件 |
| 旧 bootstrap/投稿计划 | 当前树删除，Git 历史可恢复；当前权威入口为 `project_master_plan.md` 与 `paper/jss/` |

## 恢复点

删除前恢复包位于：

`/home/xiaoyuliang/archives/vuln-adj-pre-hygiene-20260824T104541+0800`

其中 `untracked-files.tar` 保存整理前全部 4,399 个未跟踪文件，
`tracked-worktree.patch` 保存 tracked diff，`status-porcelain.txt` 保存完整路径清单。
恢复包校验值：

- `untracked-files.tar`：`e80a919f20d264013a72343f0fa9c9d93729f3c91f91c3838a6584a1369e8acd`
- `tracked-worktree.patch`：`feae02349a66a0bf805cce218a2cec2a774590524ef2f4a349e6232cf362978a`

不要在未知 HEAD 上直接套用 patch；先核对 `base-head.txt`。tar 可以按其相对路径恢复
到同一仓库根目录。

## Payload 清单

运行：

```bash
python3 scripts/build_repository_payload_manifest.py
python3 scripts/build_repository_payload_manifest.py --verify
```

生成的 `retained_local_payloads.sha256.tsv` 只证明对应字节在本机存在且未变，不能证明
数据来源权威、标签为真人、实验设计有效或结果可投稿。新增 ignored payload 后必须重建
清单；验证失败时不得静默覆盖旧清单。
