# Experimental data — version 1.0.0

A Lightweight Single-Show Anonymous Credential Scheme Supporting Anonymous Transfer

Authors, in manuscript order: Yuanshao Liang, Hui Li, Wenhui Hu, Fuli Jiang, and Naixing Wu.

This dataset contains the data underlying Figures 2–5 and Table III of the associated manuscript. Version: 1.0.0. Repository: Zenodo.

The data, sanitized metadata, and documentation are licensed under Creative Commons Attribution 4.0 International (CC BY 4.0); scripts/verify.py is licensed under MIT. The full license texts are in LICENSE-DATA.txt and LICENSE-CODE.txt. The separate licenses apply to those respective file scopes.

## Scope and reproduction

Eight original CSVs and eleven archived processed CSVs are preserved byte for byte, including their line endings. A twelfth processed CSV selects the sixteen Table III summary rows without rounding their values. Six environment records and one measurement note preserve the measurement settings and historical source/binary hashes. Private absolute build paths have been replaced by relative paths in metadata only.

This package supports recomputation and checking of numerical figure/table data. It does not contain the implementation needed to rerun all cryptographic benchmarks, historical measured-source archives, binaries, third-party libraries, typeset figure assets, the manuscript PDF, or author photographs. Historical source and binary hashes identify the measured versions; the referenced files are not included. Existing bootstrap confidence intervals are retained in the processed CSVs and checked for integrity, but the included verifier does not recompute bootstrap intervals or draw the typeset figures.

Use Python 3.10 or later; no external packages are required:

    python3 scripts/verify.py

On Windows:

    py -3 scripts/verify.py

The verifier writes no files and prints a JSON report. It checks the manifest, all file hashes and row counts, exact Figure 2 message sizes, every Figure 3 and Figure 4 plotted median, all sixteen Table III cells, all 10,001 cumulative points per scheme for each attribute setting, phase means, savings point estimates, and interpolated break-even rates. A failed check exits with a nonzero status. SHA256SUMS covers all files except itself; manifest.json inventories all files except itself and SHA256SUMS.

## Figure and table map

Paths below are relative to this package. The raw directory names retain the historical experiment identifiers.

| Paper item | Processed CSVs in data/processed | Raw inputs in data/raw |
| --- | --- | --- |
| Figure 2: issuance communication | figure_2_issuance.csv | issuance-communication/transcripts-v2.csv; transcripts.csv supplies the archived baseline comparison |
| Figure 3: first-issuance timings | figure_3_issuance_timings.csv | issuance-first-v2-typef-20261117/raw_timings.csv |
| Figure 4: presentation timings | figure_4_presentation_timings.csv | presentation-oas3-20261110/raw_timings.csv, plus presentation-verify-window-20261116/raw_timings.csv for OTAC verification at ell=64 |
| Figure 5(a): 16 attributes | figure_5_n16_workload_curves.csv, figure_5_n16_break_even.csv, figure_5_n16_savings.csv, figure_5_n16_phase_means.csv | utilization-oas3-10000-20261110-n16/raw_timings.csv |
| Figure 5(b): 32 attributes | corresponding four figure_5_n32_*.csv files | utilization-oas3-10000-20261110-n32/raw_timings.csv |
| Table III: credential transfer | table_iii_transfer.csv | attribute-scale-20261109/raw_timings.csv |

The source/source_csv fields inside archived processed CSVs intentionally retain historical project-relative labels. For example, results/<run>/raw_timings.csv maps to data/raw/<run>/raw_timings.csv here. The manifest records the original project-relative location and original/public SHA-256 for every copied source. No original private absolute location is recorded in the manifest.

The Table III file is a selection from the historical summary.csv, whose hash is recorded in the manifest. It keeps the original full-precision medians and confidence intervals. The verifier independently computes the medians from raw timings and checks the manuscript's two-decimal values.

## Measurement settings and boundaries

The experiments use Ubuntu 24.04.5 LTS on x86-64, an Intel Xeon Gold 5218 at 2.30 GHz, C++17/GCC 13.3.0 in Release mode with -O3, PBC 1.0.0, and GMP 6.3.0. The Type F group order is 510 bits. Run-specific environment files record affinities, warm-ups, seeds, source hashes, and timing boundaries; the first-issuance measurement note supplies its operating-system/compiler/CPU record.

OTAC is the internal identifier for the proposed scheme, labelled "This work" in the paper. ACL means Anonymous Credentials Light; UPROVE means U-Prove. The baselines are the local benchmark reproductions identified by the historical source hashes, rather than the original authors' historical performance measurements. Some byte-preserved raw files contain additional configurations or implementation comparisons that the present figures do not use.

The raw rows describe benchmark executions with synthetic inputs. Holder, batch, repetition, and presentation-order indices do not identify real people or production users. These files contain timing and message-size measurements, not private credentials or identity records.

Figures 3–4 use n=4,8,...,64 and 100 recorded repetitions after three warm-ups. Figure 3 selects first issuance and the holder/issuer roles; other roles and repeat-issuance rows remain in the original raw file. Figure 4 uses d=2. For OTAC, ell=32,64,128; ell does not apply to the baselines. OTAC proof-generation time is sample_ms+prove_ms. Only its ell=64 verification series comes from the later verification-window run. OAS2 rows are an archived paired implementation comparison and are not plotted. The extra n=58,59 verification measurements are also not plotted.

Table III selects OTAC, profile=pbc-native, ell=64, d=2, n=8,16,...,64 and operations transfer/verify_transfer. Each of its sixteen medians uses 100 raw measurements. Generation includes fresh randomness and candidate sampling; transport decoding and fixture/state copying are outside timing. Verification includes local checks and the local atomic state update. The raw transfer source file also preserves other benchmark operations and grids.

For Figure 5, each of six paired batches issues one credential to each of 10,000 synthetic holders, then presents credentials in the same order for all three schemes. The six scheme execution orders are balanced across batches. The two attribute settings are n=16 and n=32; both use d=2, ell=64, first-v2 issuance and OAS3 presentation encoding. Each worker warms up with three batches of 64 credentials. The two attribute configurations were scheduled concurrently, as recorded in their environment files.

For each batch and scheme, the cumulative value at k presentations is:

    [sum over all 10,000 credentials of
         (holder_issue_ms + issuer_issue_ms + admit_ms)
     + sum over the first k presentations of (show_ms + verify_ms)] / 10,000

The plotted point is the mean over six paired batches. The redemption/utilization percentage is 100*k/10,000. These are computation times per issued credential, not wall-clock service latency. The ledger is an in-memory state machine; network transmission, blockchain consensus, external eligibility checks, and public-parameter preparation are outside these measurements.

ACL's first registration generation and verification are already included in holder_issue_ms and issuer_issue_ms. Its two separate registration columns must not be added again. They support the ACL_REUSE sensitivity calculation, which subtracts those measured initial-registration costs from ACL issuance. ACL_REUSE is a derived sensitivity case, not an additional primary baseline in Figure 5.

The main break-even values interpolate between adjacent measured cumulative points. They are not the linear phase-mean model in model_pct:

| Attributes | U-Prove break-even | Adjacent presentation counts | ACL break-even | Adjacent presentation counts |
| --- | ---: | --- | ---: | --- |
| 16 | 20.19% | 2018 to 2019 | 46.25% | 4624 to 4625 |
| 32 | 28.96% | 2895 to 2896 | 56.68% | 5668 to 5669 |

Figures 3–4 archive 95% percentile-bootstrap intervals for medians using 10,000 resamples. Figure 5 archives pointwise 95% paired-batch bootstrap intervals using 10,000 resamples. The curves retain all 10,001 utilization points per scheme and attribute setting without fitting or smoothing. The verifier checks the archived files and the underlying point estimates, not the bootstrap random draws.

## Data dictionary

All CSVs have a header. Counts and byte lengths are integers; timing columns are milliseconds unless their name explicitly contains pct. Blank fields represent inapplicable values or an absent crossing, not zero.

### Shared configuration and provenance fields

| Field | Meaning |
| --- | --- |
| n | Total attribute count. |
| d | Number of disclosed/checked attributes. |
| ell | Candidate-list size for OTAC. Zero in some raw baseline records, and blank in corresponding processed records, means inapplicable. |
| scheme / baseline | Internal scheme/comparison identifier: OTAC, ACL, UPROVE; ACL_REUSE is the registration-reuse sensitivity calculation. Some preserved transfer-source rows also contain other unselected benchmark schemes. |
| experiment | Historical benchmark grid label such as algorithms, attributes, or match_counts. |
| profile | Historical implementation/scope label. Table III uses pbc-native. |
| repetition / repetitions | Recorded execution index, or number of recorded executions summarized. |
| ms | Monotonic-clock elapsed milliseconds for the named operation. |
| operation | Algorithm label; transfer and verify_transfer supply Table III; show and verify are presentation generation and verification. |
| operation_complete | Historical completion marker. Selected Table III rows have value 1. |
| bytes | Primary encoded object's payload length; this field alone is not full bilateral communication. Zero on a verifier row does not mean it received no input. |
| median_ms | Median of the selected raw timings. |
| ci95_low_ms / ci95_high_ms | Archived 95% interval endpoints, in milliseconds, for the statistic in that file. |
| source / source_csv | Original project-relative raw source label, mapped to this package by the table above. |
| source_sha256 / source_csv_sha256 | Original raw-file SHA-256, preserved unchanged. |

### Issuance communication

The two transcript files each have 96 rows: sixteen attribute counts, three schemes and two modes.

| Field | Meaning |
| --- | --- |
| mode | first or repeat issuance. |
| user_to_issuer_bytes / issuer_to_user_bytes | Exact encoded payload in the named direction. |
| bilateral_bytes | Sum of those two directional payloads. |
| user_issuer_messages | Number of one-way messages between holder and issuer. |
| ledger_bytes / ledger_messages | Separately recorded registration submission payload/count, excluded from bilateral_bytes. |
| public_credential_bytes | Encoded public credential payload length. |
| otac_first / otac_repeat | Processed bilateral OTAC payload, in bytes. |
| acl_first / acl_repeat | Processed bilateral ACL payload, in bytes. |
| uprove_submitted / uprove_known | Processed U-Prove first/repeat payload, in bytes; historical column names retained. |

Figure 2(a) converts bytes to decimal kB (1 kB = 1,000 B); Figure 2(b) uses bytes. These are exact payload counts with no sampling interval.

### Issuance and presentation timing

| Field | Meaning |
| --- | --- |
| role | holder, issuer, or admit in the first/repeat issuance timing file. |
| implementation | OAS3 is the plotted OTAC implementation; OAS2 is the archived paired variant; ACL/UPROVE identify baseline rows. |
| order | Paired old/new implementation execution order (0 or 1); -1 denotes an unpaired record. |
| sample_ms | Candidate selection time; added to prove_ms for OTAC generation. Baseline records use zero. |
| prove_ms | Proof generation time excluding the separately recorded candidate selection. |
| verify_ms | Recorded verification time in the given timing window. |
| old_verify_ms | Verification time of the paired older implementation; blank where there is no paired measurement. The processed Figure 4 update uses verify_ms. |

The first-issuance raw file has 22,400 rows. The integrated-presentation raw file has 8,100 rows; its verification update has 1,800 rows. The preserved attribute-scale source for Table III has 29,400 rows.

### Utilization raw records

Each attribute setting has 180,000 rows: six batches, three schemes and 10,000 credentials.

| Field | Meaning |
| --- | --- |
| batch | Paired batch index, 0 through 5. |
| scheme_order | Scheme execution position within a batch, 0 through 2. |
| holder | Synthetic holder index, 0 through 9,999. |
| use_order | Presentation position, 1 through 10,000; a shared permutation across schemes within a batch. |
| holder_issue_ms / issuer_issue_ms | Timed holder/issuer issuance components, including ACL first registration where applicable. |
| admit_ms | OTAC local signature checking and commitment admission; zero for these baseline rows. |
| show_ms / verify_ms | Presentation generation and verification components, including local duplicate checking in verification. |
| acl_holder_registration_ms / acl_issuer_registration_ms | Separately identified components already included in ACL issuance; used only when deriving registration reuse. Zero for other schemes. |

### Utilization processed records

| Field | Meaning |
| --- | --- |
| used / use_pct | Actual presentation count k and percentage 100*k/10,000. |
| ms_per_issued | Mean cumulative computation per issued credential across six batches. |
| saved_pct | 100*(baseline cumulative time - OTAC cumulative time)/baseline cumulative time. |
| ci95_low_pct / ci95_high_pct | Archived 95% bootstrap interval endpoints in percentage points. |
| issuance_ms / use_ms | Mean per-credential issuance/presentation totals from the phase_means file. Other phase columns have the same names and units as raw components. |
| model_pct | Crossing percentage from phase means; differs from the empirical prefix crossing and is not the manuscript headline value. |
| break_even_pct | Empirical crossing percentage interpolated between adjacent measured cumulative points. |
| bootstrap_crossing_fraction | Fraction of paired-batch bootstrap draws with a crossing. |
| issued_per_used | 100/break_even_pct, when a crossing exists. |
| cheaper_use_count / next_use_count | Last lower-cost integer presentation count and the next count, bracketing the first crossing. |
| positive_ci_through | Last count in the continuous prefix for which the savings interval's lower endpoint is at least 0%. |
| practical_ci_through | Same prefix criterion at the recorded 10% savings margin. A value of -1 means the criterion fails at zero uses. |
| saving_at_zero_pct / saving_at_zero_ci95_low_pct | Savings and its interval lower endpoint before any presentations. |

Each workload_curves CSV and savings CSV has 30,003 rows (three series including the sensitivity series where applicable, each with 10,001 counts). Each phase_means and break_even CSV has three rows. The savings series are ACL, UPROVE and ACL_REUSE; the workload curves are OTAC, ACL and UPROVE.

## Metadata, provenance and licenses

Environment files retain measured hardware/software settings, timing windows, source hashes, binary hashes, and original artifact hashes. Embedded historical artifact hashes still refer to the original measurement artifacts; they are not claims that omitted artifacts are present in this package. In particular, an embedded hash for the original measurement note differs from its sanitized public copy. Use manifest.json and SHA256SUMS to verify the files actually distributed here.

For each copied file, the manifest records its original project-relative path, original SHA-256, public SHA-256, size, and transformation note. No CSV content was changed except the explicit selection into the new Table III CSV. Original raw-file hashes in the processed files therefore remain directly verifiable.

For attribution, use the five authors in the order shown above and the dataset title in CITATION.cff. LICENSE-DATA.txt reproduces the complete CC BY 4.0 legal code from Creative Commons; LICENSE-CODE.txt contains the MIT text from SPDX with its copyright placeholders filled. The manifest records the license-source URLs and hashes.
