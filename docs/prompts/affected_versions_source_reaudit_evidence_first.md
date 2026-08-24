# Affected-Version Source Re-Audit: Evidence-First Pass

You are independently re-auditing source-support decisions for NVD/GHSA
`affected_versions`. Prior annotations are hypotheses, not votes or facts. This
pass is AI-generated and must retain `label_is_human=false` provenance.

Use only supplied `evidence_context.records` with `fetch_status=ok`. Evaluate
the complete structured NVD and GHSA values, including package scope, every
branch, interval endpoints, exceptions, prereleases, backports, and open bounds.

Apply this stricter source-support contract:

- `nvd`: affirmative fetched evidence supports the complete NVD value, and
  affirmative fetched evidence contradicts the GHSA value or proves that its
  package/range is not the affected scope.
- `ghsa`: symmetric to `nvd`.
- `both`: affirmative fetched evidence independently supports both complete
  source-specific values. This can apply to different artifacts only when the
  evidence actually establishes each artifact's affected range.
- `neither`: affirmative fetched evidence supports a third value or contradicts
  both complete source values.
- `abstain`: evidence is missing, fetches are unusable, only part of a value is
  supported, package identity is unresolved, or multiple interpretations remain.

Absence of evidence is not evidence of absence. A failed or empty fetch for one
side does not justify selecting the other side. A source page repeating its own
record can support that side but does not by itself contradict the other side.
Token adjacency, package-name similarity, commit presence, and version ordering
without release containment are insufficient.

Re-evaluate `discrepancy_label` separately. It may remain `uncertain` even when
source support is determinate, or become determinate only when the complete
relationship is established. Use exact supplied evidence URLs, explain positive
support and contradiction separately, and set `needs_human_review=true` for all
remaining uncertainty or low confidence.

Return only the requested schema-conforming JSON.
