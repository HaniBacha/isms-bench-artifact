# Metadata-Spoofing/Corruption Ablation v23

Evaluated 50 non-fulfilled or uncertain cases selected for metadata-sensitive evidence defects.
The ablation mutates metadata fields only; evidence text and labels are unchanged. Results are diagnostic and do not model a full attacker feedback loop.

| Variant | Method | Macro-F1 | False compliance | False fulfilled | Abstention | Fulfilled pred. | Risk-weighted error |
|---|---:|---:|---:|---:|---:|---:|---:|
| baseline | metadata_aware | 0.495 | 0.260 | 0.160 | 0.140 | 0.160 | 0.910 |
| baseline | provenance_balanced | 0.416 | 0.140 | 0.020 | 0.220 | 0.020 | 0.495 |
| baseline | provenance_conservative | 0.404 | 0.060 | 0.000 | 0.360 | 0.000 | 0.390 |
| baseline | provenance_conservative_with_guard | 0.404 | 0.060 | 0.000 | 0.360 | 0.000 | 0.390 |
| approval_spoof | metadata_aware | 0.495 | 0.260 | 0.160 | 0.140 | 0.160 | 0.910 |
| approval_spoof | provenance_balanced | 0.416 | 0.140 | 0.020 | 0.220 | 0.020 | 0.495 |
| approval_spoof | provenance_conservative | 0.404 | 0.060 | 0.000 | 0.360 | 0.000 | 0.390 |
| approval_spoof | provenance_conservative_with_guard | 0.404 | 0.060 | 0.000 | 0.360 | 0.000 | 0.390 |
| validity_spoof | metadata_aware | 0.495 | 0.260 | 0.160 | 0.140 | 0.160 | 0.910 |
| validity_spoof | provenance_balanced | 0.375 | 0.200 | 0.140 | 0.220 | 0.140 | 0.825 |
| validity_spoof | provenance_conservative | 0.404 | 0.060 | 0.000 | 0.360 | 0.000 | 0.390 |
| validity_spoof | provenance_conservative_with_guard | 0.404 | 0.060 | 0.000 | 0.360 | 0.000 | 0.390 |
| source_type_spoof | metadata_aware | 0.348 | 0.500 | 0.180 | 0.080 | 0.180 | 1.340 |
| source_type_spoof | provenance_balanced | 0.127 | 0.000 | 0.000 | 0.000 | 0.000 | 0.660 |
| source_type_spoof | provenance_conservative | 0.127 | 0.000 | 0.000 | 0.000 | 0.000 | 0.660 |
| source_type_spoof | provenance_conservative_with_guard | 0.127 | 0.000 | 0.000 | 0.000 | 0.000 | 0.660 |
| trust_approver_spoof | metadata_aware | 0.495 | 0.260 | 0.160 | 0.140 | 0.160 | 0.910 |
| trust_approver_spoof | provenance_balanced | 0.416 | 0.140 | 0.020 | 0.220 | 0.020 | 0.495 |
| trust_approver_spoof | provenance_conservative | 0.404 | 0.060 | 0.000 | 0.360 | 0.000 | 0.390 |
| trust_approver_spoof | provenance_conservative_with_guard | 0.404 | 0.060 | 0.000 | 0.360 | 0.000 | 0.390 |
| missing_metadata | metadata_aware | 0.271 | 0.040 | 0.000 | 0.360 | 0.000 | 0.490 |
| missing_metadata | provenance_balanced | 0.411 | 0.140 | 0.000 | 0.220 | 0.000 | 0.465 |
| missing_metadata | provenance_conservative | 0.121 | 0.340 | 0.000 | 1.000 | 0.000 | 0.510 |
| missing_metadata | provenance_conservative_with_guard | 0.121 | 0.340 | 0.000 | 1.000 | 0.000 | 0.510 |

## Interpretation

- `metadata_aware`: baseline false compliance 0.260; worst spoofed variant `source_type_spoof` reaches 0.500.
- `provenance_balanced`: baseline false compliance 0.140; worst spoofed variant `validity_spoof` reaches 0.200.
- `provenance_conservative`: baseline false compliance 0.060; worst spoofed variant `missing_metadata` reaches 0.340.
- `provenance_conservative_with_guard`: baseline false compliance 0.060; worst spoofed variant `missing_metadata` reaches 0.340.

False compliance follows the paper's ordinal definition, where `unclear` can be more compliant than `not_fulfilled`. The stricter `false_fulfilled_rate` column separates full false-fulfilled outcomes from conservative uncertainty.

Metadata spoofing is therefore a direct threat to provenance-aware assessment. The result should be reported as a diagnostic stress test, not as evidence of real-world robustness.
