# RQ3 Case-Study Sketch Table

Generated from existing RQ3 silver-label artifacts. These examples are interpretive sketches, not new human gold labels.

| Pattern | CVE | Field | NVD value | GHSA value | Silver reading | Evidence note |
| --- | --- | --- | --- | --- | --- | --- |
| Severity evidence supports both sources | CVE-2023-43637 | severity | HIGH | MODERATE | silver source=both; baseline=both; matches_silver=True | ok=6; ok hosts: github.com, asrg.io, nvd.nist.gov |
| Severity evidence supports one source | CVE-2024-38503 | severity | MEDIUM | HIGH | silver source=nvd; baseline=nvd; matches_silver=True | ok=7; ok hosts: github.com, www.openwall.com, syncope.apache.org, nvd.nist.gov |
| Severity silver-label mismatch | CVE-2023-5588 | severity | MEDIUM | LOW | silver source=both; baseline=nvd; matches_silver=False | http_403=2, ok=5; ok hosts: github.com, nvd.nist.gov |
| Severity abstention/manual review | CVE-2024-27456 | severity | CRITICAL | MODERATE | silver source=abstain; baseline=both; matches_silver=False | ok=6; ok hosts: github.com, nvd.nist.gov |
| Affected_versions baseline false positive | CVE-2023-29293 | affected_versions | 8 span(s): 2.3.7; 2.4.0; 2.4.1; +5 more | 2 span(s): introduced 2.4.4-p1, >=2.4.4-p1, <2.4.4-p4, fixed 2.4.4-p4; introduced 2.4... | silver label=incomplete; baseline false positive=yes; source=nvd | ok=1, timeout=2; ok hosts: nvd.nist.gov |
| Affected_versions residual conflict | CVE-2024-47003 | affected_versions | 2 span(s): 9.11.0; introduced 9.5.0, >=9.5.0, <9.5.9 | 1 span(s): <8.0.0-20240806094731-69a8b3df0f9f, fixed 8.0.0-20240806094731-69a8b3df0f9f | silver label=factual_conflict; baseline false positive=no; source=nvd | ok=3, url_error=3; ok hosts: mattermost.com, github.com, nvd.nist.gov |
