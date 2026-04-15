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
