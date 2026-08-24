# Hutool Maven Release Graph Contract v1

## Status and boundary

This is a post-unsealing mechanism diagnostic for the third-ranked repeated
`affected_versions` project family. It is not a human annotation contract, a
gold-label source, an accuracy estimate, or a production rule.

Protocol discovery occurred before v1 was frozen. The discovery observed that:

- Maven Central exposed the same 214 version tokens for `cn.hutool:hutool-all`,
  `cn.hutool:hutool-core`, and `cn.hutool:hutool-json`;
- 209 of those tokens matched the stable `MAJOR.MINOR.PATCH` grammar, while five
  milestone tokens did not;
- source `hutool-all/pom.xml` files at `5.8.19`, `5.8.21`, and `5.8.22`
  declared same-parent-version dependencies on `hutool-core` and `hutool-json`;
- the corresponding Maven Central `hutool-all` JARs contained compiled classes
  under both `cn/hutool/core/` and `cn/hutool/json/`.

Because those facts shaped this contract, every output must retain
`protocol_discovery_disclosed=true`, `post_unsealing=true`, and
`candidate_promotion_allowed=false`. A successful run can only motivate a new
blind cohort under a pre-frozen contract.

## Fixed rows

The input is the sealed D worklist and its sealed manifest. The parent edge
audit must retain Hutool at eligible rank 3 with score 8. The only rows are:

| Sample | CVE | NVD product claim | GHSA Maven claim |
|---|---|---|---|
| `rq2_typing_holdout_v1:328` | `CVE-2023-3276` | Hutool through `5.8.19`, inclusive | `cn.hutool:hutool-core`, introduced at `0`, no upper bound |
| `rq2_typing_holdout_v1:1164` | `CVE-2023-42276` | singleton Hutool `5.8.21` | `cn.hutool:hutool-core` and `cn.hutool:hutool-json`, each introduced at `0`, no upper bound |

The analyzer must reject any row identity, subject, ecosystem, or boundary
drift before reading registry evidence.

## Frozen evidence interfaces

The analyzer caches response bodies and fetch metadata for:

1. Maven metadata for `hutool-all`, `hutool-core`, and `hutool-json`;
2. official repository source POMs for `hutool-all` at `5.8.19`, `5.8.21`, and
   `5.8.22`;
3. Maven Central aggregate JARs for the same three versions.

The cache hash, source URL, HTTP status, and result/input hashes are mandatory
manifest fields. The verifier must work from the cache only and must not make
network requests.

## Release domain

The extensional product domain is the exact intersection of the three cached
Maven catalogs after retaining only tokens matching `^[0-9]+\.[0-9]+\.[0-9]+$`.
The five discovered milestone tokens are fixed exclusions:

- `5.8.0.M1`
- `5.8.0.M2`
- `5.8.0.M3`
- `5.8.0.M4`
- `5.8.4.M1`

All three stable catalogs must be identical. Versions are ordered as integer
triples. This snapshot-extensional domain does not claim that Maven Central is
a complete historical Hutool release universe or that an unbounded advisory
has a human-approved temporal interpretation.

## Identity and containment gates

Every case requires all of the following:

1. sealed row identity and claim signature are unchanged;
2. all Maven metadata coordinates match their requested coordinates;
3. all three stable version catalogs are identical and contain all claim
   boundaries plus witness release `5.8.22`;
4. the five milestone tokens are excluded exactly as declared above;
5. each source POM binds `cn.hutool:hutool-parent` and `hutool-all` to the URL
   version, declares `jar` packaging, directly depends on both required
   components at `${project.parent.version}`, and configures the Maven shade
   goal;
6. each aggregate JAR contains non-empty compiled-class sets for both required
   package prefixes.

Catalog equality establishes a total release-token correspondence in the
frozen domain. POM/JAR checks establish aggregate/component containment only at
the three fixed critical anchors. The output must preserve that distinction;
it must not claim that every historical aggregate JAR was inspected.

## Set interpretation

Only after every gate passes:

- a GHSA range introduced at `0` with no upper bound denotes every release in
  the relevant cached component catalog;
- the two-component GHSA claim denotes the union of its component sets;
- the NVD interval or singleton is evaluated over the same stable release
  domain;
- equal sets map to `representation_discrepancy`, a strict subset in either
  direction maps to `incomplete`, and partial overlap or disjoint sets map to
  `factual_conflict`.

This label is a Codex development candidate only. No row can be added to the
1,219-row non-human combined candidate, and reported coverage remains
`1,219/1,250 = 0.9752`.

## Advancement gate

Both fixed rows must pass for the family mechanism gate to pass. A 2/2 result
has status `mechanism_pass_requires_new_blind_cohort`; otherwise the result is
`no_go_hutool_maven_release_graph_unstable`. Neither status permits candidate
promotion, an accuracy claim, human-gold language, or a production switch.
