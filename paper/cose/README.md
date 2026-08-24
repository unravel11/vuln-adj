# COSE Draft Workspace

当前目标期刊暂定为 `Computers & Security (COSE)`。

## 文件边界

Submission-facing draft components:

- `title_page.md`
- `abstract.md`
- `highlights.md`
- `sections/`
- `references.md`
- `references.bib`
- `declarations.md`
- `figures/method_framework.svg`
- `figures/method_framework.png`
- `full_draft.md`
- `latex/`

Internal planning/checklist files only. Do not include these files in a journal submission package:

- `cover_letter_draft.md`
- `method_explainer.html`
- `submission_readiness.md`
- `outline.md`
- workspace README/checklist files

建议维护内容：

- `sections/`：章节草稿与写作碎片
- `figures/`：论文图
- `tables/`：论文表格或表格来源说明
- `method_explainer.html`：方法章节讲解页，用于内部写作和汇报，不进入投稿包
- `outline.md`：内部稿件结构与写作约束
- `latex/`：由 Markdown 与 artifact 生成的 Elsevier/elsarticle scaffold

## 当前可复现检查

核心生成命令：

```bash
.venv/bin/python experiments/paper_artifacts/build_rq1_figures.py
.venv/bin/python experiments/paper_artifacts/build_cose_tables.py
.venv/bin/python experiments/paper_artifacts/build_cose_case_studies.py
.venv/bin/python experiments/paper_artifacts/build_cose_bibtex.py
.venv/bin/python experiments/paper_artifacts/build_cose_manuscript.py
.venv/bin/python experiments/paper_artifacts/build_cose_latex.py
.venv/bin/python experiments/paper_artifacts/validate_cose_package.py
```

`validate_cose_package.py` 会写出 `results/paper_cose/cose_package_manifest.json`，记录生成器、输入/输出 hash、同步检查、LaTeX 编译检查和 submission blockers。当前允许 hard validation 通过但 `submission_ready=false`，因为作者/声明占位符和 RQ2/RQ3 human-gold 阶段尚未完成。

当前写作边界：

- 先固定任务定义、方法边界与实验设计
- 结果未跑出前，不在正文中写具体数值结论
- 涉及相关工作与引用时，只写已确认来源
- 内部 planning/checklist 文件不得混入生成的 `full_draft.md` 或 `latex/main.tex`
