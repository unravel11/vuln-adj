# RQ2 Residual Non-Affected Evidence Contract v1

## Purpose and boundary

This contract audits the two `cwe_ids` rows and one `references` row that remain
unresolved after the RQ2 D/E evidence-secondary stage. The target is selected
from revealed non-human outcomes, and protocol discovery inspected source-code,
CWE-mapping, and malformed-URL evidence before v1 was written. Every artifact
must therefore retain:

- `post_unsealing_targeted_diagnostic=true`;
- `protocol_discovery_disclosed=true`;
- `selection_uses_prior_unresolved_status=true`;
- `candidate_promotion_allowed=false`;
- `eligible_for_human_gold_claim=false`;
- `label_is_human=false`.

The audit can produce development candidates and construct no-go findings. It
cannot increase the `1,219/1,250` combined RQ2 candidate, estimate accuracy, or
replace real-person review.

## Fixed cohort

The cohort is exactly:

| Sample | CVE | Field |
|---|---|---|
| `rq2_typing_holdout_v1:1118` | `CVE-2024-8020` | `cwe_ids` |
| `rq2_typing_holdout_v1:1023` | `CVE-2023-4304` | `cwe_ids` |
| `rq2_typing_holdout_v1:787` | `CVE-2023-32187` | `references` |

The builder must reconstruct this set as all D/E rows with
`secondary_strict_consensus=false` and `field != affected_versions`. It seals a
projection of the original source rows before analysis. Prior reviewer
rationales and candidate labels may establish cohort membership but must not be
copied into the analysis worklist.

## Frozen evidence

The evidence cache contains complete response bodies and metadata for these
fixed resources:

- PyTorch Lightning tag `2.3.2` source at commit
  `056bb0834b8fca739dec3e731b01f2f6631be142`, its GitHub global advisory, and
  official CWE-248/CWE-400 definitions;
- the Froxlor fixing patch at
  `ce9a5f97a3edb30c7d33878765d3c014a6583597`, its GitHub global advisory, and
  official CWE-840/CWE-284/CWE-862 definitions;
- the K3s GitHub global advisory and the two supplied malformed SUSE Bugzilla
  resources.

HTTP failures, hash drift, a changed tag commit, or a missing required marker
force `uncertain`. No analyzer network access is allowed.

## Case gates

### CVE-2024-8020

The source gate requires the cached `post_state` handler to:

1. bind `POST /api/v1/state`;
2. parse a request body;
3. directly index `body["state"]` on the non-`stage` path; and
4. contain no local `try` handler around that path.

The GitHub advisory must assign CWE-248, while the source row assigns NVD
CWE-400 and GHSA CWE-248. The official pages must define CWE-248 as an uncaught
exception and CWE-400 as uncontrolled resource consumption. When all gates
pass, the source directly supports the uncaught-exception mechanism but does
not establish the disjoint resource-consumption claim in this handler; the
development discrepancy candidate is `factual_conflict`. Otherwise it is
`uncertain`.

This is a source-local mechanism judgment. It does not prove that resource
consumption is impossible elsewhere in the product.

### CVE-2023-4304

The official CWE page must identify CWE-840 as a Category whose mapping to
real-world vulnerabilities is prohibited. The cached patch must add non-empty
name/email validation in `Admins.update()`. If the changed executable lines do
not establish an authorization decision or actor/resource permission check,
the evidence is insufficient to relate prohibited category CWE-840 to
CWE-284/CWE-862 for this concrete issue. The result remains `uncertain`; the
contract does not infer access-control semantics from the advisory label.

### CVE-2023-32187

Two explicit reference-identity profiles are evaluated:

- `frozen_http_resource`: retain the exact supplied URL strings. The two
  malformed Bugzilla query values are distinct successful HTTP resources.
- `intended_bug_lookup_repair`: repair only a terminal `https:/` or `https://`
  appended to an otherwise complete `CVE-YYYY-NNNN` Bugzilla `id` value, making
  both strings the same intended lookup resource.

The first profile yields overlapping non-subset sets and therefore
`representation_discrepancy`; the second yields an NVD strict subset of GHSA
and therefore `incomplete`. Because the profiles disagree and no real person
has approved either resource-identity construct, the row remains `uncertain`.

## Advancement

The expected diagnostic outcome is one development `factual_conflict` and two
`uncertain` rows. Every `promoted_candidate` is null. A different result is a
contract failure, not grounds to revise the rule on these revealed rows.
