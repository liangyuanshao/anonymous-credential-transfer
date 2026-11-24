# Current measurement data

Current data are saved in `results/current/` and current figures in
`figures/current/`. The official U-Prove runtime reference and the structural
issuance message counts are stored separately. The plots use only the shared
PBC experiment.

## Raw timing records

`raw_timings.csv` contains one record per measured algorithm execution:

```text
experiment,scheme,profile,operation,ell,n,d,repetition,ms,bytes,operation_complete
```

| Field | Meaning |
| --- | --- |
| `experiment` | `algorithms` for the default point, `attributes` for other total counts, `match_counts` for other matched counts |
| `scheme` | `OTAC`, `ACL`, `UPROVE`, or `CY22` |
| `profile` | Implementation/scope label, including `pbc-native`, `pbc-algebraic`, `honest-party-core`, `and-equations` |
| `operation` | `holder_issue`, `issuer_issue`, `show`, `verify`, `transfer`, or `verify_transfer` |
| `ell` | Fixed candidate list size (64); relevant to OTAC only |
| `n`, `d` | Total attributes and attributes checked against public equality values |
| `repetition` | Recorded repetition index, `0` through `99` |
| `ms` | Measured monotonic-clock elapsed time in milliseconds |
| `bytes` | Recorded primary object's payload length, not necessarily the full interaction's communication |
| `operation_complete` | `0` only for the incomplete CY22 issuance core; `1` otherwise |

The full grid has **14,400 records across 144 series**, each with 100 recorded
executions after three unrecorded warm-ups:

- Four total attribute counts `n=2,3,4,5` at `d=2` give 72 series.
  The `(2,2)` point is labelled `algorithms`; the other three are labelled
  `attributes`.
- Four additional matched counts `d=1,3,4,5` at `n=5` give 72 series labelled
  `match_counts`. The matched-count sweep reuses the `(5,2)` data.
- Each configuration records four operations for each of four schemes and
  two OTAC transfer operations, with the same `ell=64` in all configurations.

These are local measurements of the listed reproductions, not historical author
benchmark numbers. Baselines do not use OTAC's candidate-list parameter.

## Inputs and timing boundaries

`input_attributes.csv` records the public synthetic field encodings for each
attribute vector. Attributes and the holder's existing identity secret `x` are
prepared before timing. OTAC's `r` is sampled inside `cred_gen`; proof masks,
consumption rerandomization and the receiver's new `r_B` are generated inside
their timed algorithms. Baselines retain the individually documented boundaries
in their README files; an initial-opening exclusion is not imposed on all four
protocols.

Every decoy candidate is genuinely signed and admitted to the synthetic ledger.
Its opening is discarded before measured proofs. Each repetition uses a fresh
credential and an independent copy of the registered pool. Candidate position
is random, and partial Fisher–Yates candidate sampling is inside the OTAC
ProofGen/Transfer timer.

Every verification executes on parsed PBC objects. One output consumption and
transfer message per configuration is actually serialized, decoded and checked
outside timing to confirm wire round trips. Dedicated rejection tests cover
malformed encodings. Transport decoding is excluded from the timer; candidate
membership/uniqueness checks, transcript hashing, full proof equations and
atomic local state updates are included in every verification measurement.
Consumption and transfer each receive a separate copy of the pre-consumption
ledger, because the measurements are isolated algorithm calls. Rejection tests
exercise their competition against a shared state, replay, changed fields and
spent old versions.

The ledger is a local state machine. No network, chain consensus, throughput,
document inspection or confirmation delay is measured. Current service requests
contain attribute equalities and no session nonce; the data do not establish
session binding.

## Communication and setup records

`communication.csv` has columns:

```text
experiment,scheme,ell,n,d,quantity,bytes,operation_complete,basis
```

`quantity` names the measured payload or wire object. OTAC entries distinguish
request, bilateral issuance, issuance with one registration submission,
credential, joint consumption proof, full consumption, joint transfer proof,
full public transfer submission, and canonical wire encodings. `basis` records the inclusion
boundary. Wire version/shape headers are separate from cryptographic payloads.
Full consumption and transfer include the candidate list.
The `transfer` quantity is the public ledger submission; it excludes the prior
private handoff of the old commitment and opening. That separate handoff has
`B_G+(n+1)B_q` fixed cryptographic bytes, not an additional measured proof object.

Baseline rows distinguish issuance, credential and presentation. CY22 exposes
`issuance_core_lower_bound`, never a fabricated complete issuance value.
`bytes=0` on verification timing rows means no primary output object is counted;
it does not mean the verifier received no proof.

`setup.csv` records PBC context initialization, repeated common parameter/key
initialization, and Paillier key generation separately. Their costs are not
amortized into a selected online algorithm without an explicit statement.

## Summary, provenance and checks

Run `scripts/audit_results.py` for the current native outputs. Run
`scripts/plot_results.py --prepare-only` to validate the measured plotting grid
and prepare summaries/TeX. The same entry compiles the standalone PGFPlots sources when run without
`--prepare-only`.

`summary.csv` groups by
`experiment,scheme,profile,operation,ell,n,d`. It reports repetition count,
median milliseconds and the 95% percentile-bootstrap interval for the median.
All records are retained. Each group uses 10,000 bootstrap resamples with seed
`20261107 + group_index`, where `group_index` is the zero-based lexicographic
ordering of these group keys. No interpolation or synthetic timing point fills
a missing run.

The figure directory contains `comparison_source_data.csv`,
`anonymity_source_data.csv`, and `attributes_source_data.csv`. Each plotted row
retains its source CSV and SHA-256, the `ell` field from the native record, and
whether that parameter applies. Every point in the total-count and
matched-count curves comes from a measured configuration. The two sweeps
share the same measurements at `(n,d)=(5,2)`.

`environment.json` and the audit files record the machine, compiler, libraries,
parameters, source/binary hashes and checked data hashes. `data_audit.json`
records row/series counts, confidence-interval settings and the plot generator
hash. `contract.json` states the figure purpose, source boundary and limitations.
Compiled figures include selectable PDF text and versioned PNG previews for
visual checking.

Functional correctness, provenance checks and running-time measurements do not
complete the system's security proofs or establish security-model equivalence
between the compared schemes.
