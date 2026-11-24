# Figure and measurement contract: current

Scope: cryptographic communication and single-threaded local computation.
No network, consensus, throughput or deployment measurements.

The manuscript construction has seven algorithms, including anonymous
transfer. Figures 1–3 use results/current/raw_timings.csv. Figure 4 uses the
paired workload data in results/utilization. Candidate count ell=64 is fixed
throughout the current OTAC measurements. Default n=d=2.

- Figure 1: four schemes' holder-side issuance, issuer-side computation,
  presentation generation and presentation verification versus total
  attribute count n=2,3,4,5, with d=2.
- Figure 2: OTAC transfer generation and verification versus the same total
  attribute counts.
- Figure 3: four schemes' presentation cost versus the matched attribute
  count d=1,2,3,4,5, with n=5. The two scans share their (5,2) measurements.
- Figure 4: mean cumulative cost and low-use savings for 64 newly issued
  credentials per batch, with pointwise paired-bootstrap intervals for savings.

Drawing backend: XeLaTeX/PGFPlots. Python validates measurements, computes
statistics, writes tables and renders compiled PDF previews for inspection.
Deliver standalone .tex, .pdf, .png, source .csv and QA. The existing four-scheme
palette and semantic markers are preserved. The report table labels CY22
issuance as core-only.

Each microbenchmark series uses 3 warmups and 100 technical repetitions, with no discarded
records. Centers are medians, error bars are percentile-bootstrap 95% intervals
with 10000 resamples. This is not a comparison of independent deployments.
Each series retains its raw source hash, parameters and completeness flag.

Verify includes local registered-list queries and atomic state updates. Decode
and fixture/state copies are outside timing. Generation includes random sampling,
actual proof randomness, opening checks and the complete Fiat-Shamir transcript.
Only valid equality policies are benchmarked. The benchmark does not add omitted
CY22 encryption proofs or claim equal security models across schemes.
