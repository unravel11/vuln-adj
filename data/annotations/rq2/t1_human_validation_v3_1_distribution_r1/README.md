# V3.1 Calibration-1 Distribution Revision R1

Status: `ONBOARDING_PREPARED_DISTRIBUTION_BLOCKED`

The author has selected two doctoral students as the intended reviewers. They
are treated as `doctoral_student_trained_analyst`; no practitioner or
maintenance-professional expertise is claimed.

This directory does not contain a distributable case bundle. The frozen source
packets remain under `../t1_human_validation_v3_1/` with
`distribution_allowed=false` and `human_labels=0`.

Before any case is shown:

1. each reviewer completes and signs a private onboarding form;
2. the author records the applicable ethics/recruitment determination;
3. the author signs the exact guideline/hash and action-only scope approval;
4. only hashes and non-identifying qualification summaries enter
   `approval_record.json`; and
5. the builder and independent validator must both pass.

The builder can release only reviewer A/B calibration-1 action CSV bundles.
Reason, calibration-2, formal, internal, policy, AI, and other-reviewer files
are fail-closed exclusions.

Commands from the repository root:

```bash
python experiments/rq2_discrepancy_typing/build_t1_human_validation_distribution_v3_1.py --check-only
python experiments/rq2_discrepancy_typing/build_t1_human_validation_distribution_v3_1.py
python experiments/rq2_discrepancy_typing/validate_t1_human_validation_distribution_v3_1.py
```

The current check must exit `2`. Do not edit it to pass; complete the real
governance evidence first.

