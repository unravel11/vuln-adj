# RQ2 Post-profile Reference-difference Partition Contract v1

## Scope

This audit covers the complete five-row `references` union where either frozen
resource-identity profile differs from `current` in the 5,948-CVE
snapshot-external eligible universe. It is an outcome-complete, post-hoc,
same-snapshot development diagnostic, not a sample or field-complete audit.

The union contains five original-profile differences and three audited-profile
differences. The two original-only rows isolate encoded GitHub line selectors;
the shared three rows isolate GitHub advisory aliases. These counts and profile
values are author-only until both reviews finish.

## Profile-independent labels

Reviewers construct two partitions over every unique raw URL in each row:

- `underlying_reference_resource_v1`: URLs share a group only when they denote
  the same persistent document, advisory, repository artifact, or revision/path.
  A GitHub fragment or percent-encoded line selector does not create a new
  underlying file when repository, revision, and path are otherwise identical.
  Advisory URLs may share a group only when a stable advisory identifier or
  frozen evidence binds them.
- `frozen_http_resource_v1`: URLs share a group only when the frozen probes give
  positive same-resource evidence through a common final URL, a common complete
  body hash, or the same stable identifier observed in usable responses.
  Fetch failure alone proves neither sameness nor difference; return
  `insufficient` when it prevents a complete partition.

The definitions are frozen before review and reported separately. Results may
not select whichever definition favors a profile.

## Evidence and blinding

- Bind the prediction census, its parent snapshot inputs, the audited-profile
  manifest, profile implementations, probe implementation, contract, prompt,
  builder, runner, merge, and independent verifier.
- Freeze one `rq2_reference_probe_v2` record and cache-file hash for every unique
  raw URL in all five rows, including failed requests. Review-time lookup is
  forbidden.
- Reviewer worklists expose neutral review/member IDs, raw URLs, frozen probes,
  and the two definitions. They omit source side, direct CVE field, profile
  names and values, transformation trigger, prior labels, correctness, gold,
  and selection reason.
- URL text can reveal a CVE identifier and the alias structure reveals why a row
  may matter. Therefore direct fields are masked, but
  `selection_blinding_complete=false` and
  `cve_identifier_blinding_complete=false`.
- Reviewer E uses URL structure before probes. Reviewer F uses probes before URL
  structure. Worklist orders are exact reverses and run/session sets are
  disjoint.

## Merge and evaluation

Canonicalize partitions as sorted sets of sorted member-ID sets before
comparison. Strict consensus for a definition requires identical determinate
partitions, high/medium confidence, and no further-review request from either
reviewer. Any disagreement or insufficient verdict remains unresolved; there
is no third same-model vote.

Only after review, restore NVD/GHSA membership and derive the reference status:
equal resource sets are `equivalent`, a strict subset is `incomplete`, an
overlap non-subset is `representation_discrepancy`, and a disjoint result uses
the frozen reference comparator's host-overlap rule.

Report the common five-row denominator for current/original/audited comparisons,
the profile-specific difference counts (5, 3, and 2), directional agreement,
unresolved/neither counts, and conditional exact two-sided diagnostics. The
smallest possible p-values are 0.0625 for five one-direction original rows and
0.25 for three one-direction audited rows; no significance or promotion gate is
allowed.

## Claim boundary

- `uses_any_labels=true`, `uses_human_labels=false`, and
  `label_is_human=false` after review.
- No human-gold, absolute-accuracy, prevalence, confirmatory-gain, temporal,
  preregistered-power, independent-human-agreement, promotion, or production
  claim is allowed.
- The sealed 250-row evaluation and all real-person review requirements remain
  unchanged.
