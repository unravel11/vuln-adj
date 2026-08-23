# Submission Blockers

Current decision: `NO_GO_FOR_SUBMISSION`.

| Class | Item | Required by | Current evidence or status | Owner | Blocks submission? |
|---|---|---|---|---|---|
| Scientific | T1 independent human construct validation | RQ2 and any taxonomy-performance claim | Protocol only; 0/300 real-human labels | Authors and two external real reviewers | Yes |
| Scientific | T2 binary-versus-type-first downstream utility | Central action-oriented framing | Not implemented or run | Authors | Yes |
| Scientific | T3 human-backed adjudication comparison, if adjudication remains a core contribution | Positive adjudication-method claim | Current affected-version result is a non-human no-go | Authors | Conditional: yes if core, otherwise remove the claim |
| Scientific | Temporal cohort, if future-snapshot generalization remains a claim | Temporal-validity claim | Strict event-time cohort unavailable | External data availability | Conditional: remove claim or wait |
| Manuscript | JSS manuscript source | Complete paper | Only brief, ledgers, and S2 candidate plan exist | Authors | Yes |
| Manuscript | Related-work differential against closest discrepancy and affected-version studies | Novelty and positioning | Closest work identified; synthesis not yet written | Authors | Yes |
| Manuscript | COSE-to-JSS compression and result selection | Coherent JSS paper | Historical COSE draft is 88 pages and contains extensive post-hoc detail | Authors | Yes |
| Format and artifact | Current JSS author-guide, template, declarations, and artifact checks | Venue compliance | Scope checked 2026-08-23; full current submission requirements not yet frozen | Authors | Yes at S6/S7 |
| Author metadata | Title, author order, affiliations, corresponding author, funding, conflicts, CRediT, data/code and AI-use statements | Submission form and manuscript | Unresolved placeholders | Authors | Yes |
| External action | Upload and submit | Submission | Not requested and not performed | Corresponding author | Yes |

## Earliest admissible path

1. Freeze and approve the T1 codebook and reviewer packets before any real
   annotation.
2. Complete T1 without exposing baseline or model outputs to reviewers.
3. Preserve the full outcome, including uncertain labels and failed fields.
4. Freeze and run T2 on T1 labels.
5. Decide whether the resulting paper is a positive routing study or a
   construct-ambiguity/negative study.
6. Only then draft the JSS manuscript and re-run venue, artifact, and metadata
   gates.
