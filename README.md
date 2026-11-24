# Anonymous credential transfer — reproducibility package

Version: **1.0.0**

Associated manuscript: **A Lightweight Single-Show Anonymous Credential Scheme Supporting Anonymous Transfer**.

Authors, in manuscript order: Yuanshao Liang, Hui Li, Wenhui Hu, Fuli Jiang, and Naixing Wu.

Repository: https://github.com/liangyuanshao/anonymous-credential-transfer

[中文使用说明](使用说明.md)

This repository supplies the benchmark implementation, preserved measured-source versions, and experimental data for Figures 2–5 and Table III. It provides two reproducibility paths: checking the published numerical results from the archived measurements, and rebuilding the corresponding native benchmarks to collect new measurements.

## Contents

| Path | Purpose |
| --- | --- |
| `data/` | Original and processed CSVs, sanitized measurement metadata, data dictionary, and the standard-library numerical verifier. Its 34 files are preserved byte for byte from the separately prepared data package. |
| `source/current/` | Current authored C++ implementation, local baseline implementations, tests, parameters, and original build/analysis scripts. |
| `source/measured/` | Five distinct source archives from the six recorded measurement runs. The n=16/n=32 utilization source archives are identical and stored once. |
| `source/snapshots.json` | Figure/table-to-source mapping, archive hashes, recorded environment files and native entry points. |
| `tools/build_snapshot.py` | External build adapter for measured archives that have no complete standalone CMake project. It verifies source hashes and extracts into a fresh work directory. |
| `tools/verify_package.py` | Package integrity, measured-source hash and numerical-data checks. |
| `manifest.json`, `SHA256SUMS` | Inventory and integrity checks for distributed files. |

The current implementation includes changes made after the recorded measurements. **Use the measured snapshots for the paper's benchmark versions.** Their bytes are checked against the `source_sha256` records in the measurement metadata. Historical staging scripts can depend on local directories; the direct entry points below avoid those staging dependencies. The original archives remain unchanged.

## 1. Verify the archived numerical results

Python 3.10 or later is sufficient; no third-party Python packages are needed:

```sh
python3 -B tools/verify_package.py
```

On Windows, use `py -3 -B tools/verify_package.py`. To check only the data, run `python3 -B scripts/verify.py` from `data/`.

The data verifier recomputes the plotted point estimates, transfer medians and empirical break-even points from archived raw measurements. Archived bootstrap intervals are integrity-checked, but bootstrap resampling and the typeset plots are not rerun by this verifier. See [data/README.md](data/README.md) for timing boundaries, schemas and the figure/data map.

## 2. Build the implementation and dependencies

Requirements are C++17, CMake 3.18 or later, a C/C++ compiler, GMP development files and OpenSSL Crypto development files. The measured environment used Ubuntu 24.04.5, GCC 13.3.0, PBC 1.0.0 and GMP 6.3.0. Run-specific settings are in `data/metadata/`.

Build the current implementation and the pinned PBC source with:

```sh
cd source/current
sh scripts/bootstrap.sh
ctest --test-dir build --output-on-failure
cd ../..
```

`bootstrap.sh` downloads PBC 1.0.0 from its official distribution and verifies this SHA-256 before extraction:

```text
18275a367283077bafe35f443200499e3b19c4a3754953da2a1b2f0d6b5922dc
```

Official dependency sources: [PBC](https://crypto.stanford.edu/pbc/), [GMP](https://gmplib.org/), and [OpenSSL](https://www.openssl.org/). PBC's source and compiled libraries are downloaded/built locally; they are not bundled in this repository. The Windows bootstrap script accepts a `ToolchainRoot` argument for a compatible GCC/GMP/OpenSSL installation.

Passing the current implementation's tests does not establish that its timings reproduce a historical run. The next step selects the historical source explicitly.

## 3. Build a measured snapshot

List the available versions and target names:

```sh
python3 tools/build_snapshot.py --list
```

For example, after the dependency build above:

```sh
python3 tools/build_snapshot.py --snapshot first-issuance \
  --pbc-source source/current/vendor/pbc-1.0.0 \
  --pbc-library source/current/build/libpbc_local.a
```

This builds `issuance_timing` and `issuance_communication` in `.work/first-issuance/`. Use the same command with a different `--snapshot` value for the other rows below. `--target` selects one target; `--prepare-only` verifies and extracts without compiling. `--gmp-include`, `--library-directory` and `--compiler` support nonstandard dependency/toolchain locations. Existing output directories are never overwritten; choose a fresh `--output` to repeat a build.

Run each executable **from its extracted snapshot directory**, so that `parameters/type-f.param` is resolved correctly. The adapter uses `-O3 -DNDEBUG -std=gnu++17` and links PBC, GMP, OpenSSL Crypto and the math library.

| Paper item | `--snapshot` | Target | Reference run arguments after the executable |
| --- | --- | --- | --- |
| Figure 2 implementation | `first-issuance` | `issuance_communication` | `parameters/type-f.param` |
| Figure 3 | `first-issuance` | `issuance_timing` | `parameters/type-f.param 100` |
| Figure 4: generation and baseline verification | `presentation-main` | `presentation_integrated_bench` | `parameters/type-f.param 100` |
| Figure 4: OTAC verification at ell=64 | `presentation-verification` | `presentation_verify_window_bench` | `parameters/type-f.param 100` |
| Table III | `transfer` | `comparison_bench` | `bench parameters/type-f.param 100 NEW_OUTPUT wide 64` |
| Figure 5(a)/(b) | `utilization` | `utilization_bench` | `parameters/type-f.param 6 first-v2 16 10000` / `parameters/type-f.param 6 first-v2 32 10000` |

Redirect standard output to new CSV files where applicable, never over the archived data. Table III writes a fresh output directory and its transfer/verify_transfer rows are selected at n=8,16,...,64, d=2 and ell=64. Figure 5 uses six paired batches; its two attribute configurations were scheduled concurrently in the recorded experiment. To control CPU affinity on Linux, prefix an executable with `taskset -c ALLOWED_CPU`, choosing an available CPU on your machine rather than blindly copying the original CPU index.

For short execution checks, the presentation-main binary accepts `parameters/type-f.param 1 32 64`, the presentation-verification binary accepts `parameters/type-f.param 1 16`, and the utilization binary accepts `parameters/type-f.param 6 first-v2 16 64 0` (one paired batch). These checks produce fresh measurements and do not reproduce the archived full experiment.

Figure 2 has no independent archived environment record. The first-issuance snapshot contains its communication implementation; this is a related implementation source, not a claim of independently verified execution provenance for that specific communication run. All six archived timing environments' recorded source hashes match the supplied measured-source archives.

## Validation performed for this release candidate

On 2026-11-24, all five measured benchmark entry points were compiled and completed small execution checks on the local Windows/MinGW toolchain, reusing installed PBC, GMP and OpenSSL libraries. The checks covered first issuance, integrated presentation, the verification-window implementation, transfer generation/verification, and one utilization batch with 64 synthetic credentials. All compile and run exit codes were zero. In addition, the communication executable rebuilt from the first-issuance snapshot reproduced all 96 archived transcript rows with every CSV field equal. Package integrity and archived numerical-data verification also passed.

These checks establish that the preserved entry points execute with the tested local dependencies. They do not constitute a clean-machine installation test, a repeat of the six-by-10,000-credential measurements, or a repeat of the archived bootstrap analysis. Fresh check outputs did not replace the archived measurements.

## Interpretation and scope

ACL and U-Prove here are local benchmark reproductions of the published mechanisms. They are not the original authors' historical measurements or the Microsoft U-Prove SDK. The separate original Microsoft reference tree is not included or required by the native C++ comparisons. Provenance and reference notes retained under `source/current/historical-docs/` and the baseline directories describe earlier development; the measurement metadata and snapshot mapping above govern this release.

These benchmarks use synthetic inputs and an in-memory ledger state machine. The reported times exclude blockchain consensus, network delay and external eligibility checks. Hardware, library builds, scheduling, random samples and timing windows affect new measurements. Checking the archived numerical values and rerunning the native benchmarks answer different questions; exact millisecond equality across machines is not a reproducibility requirement.

The package excludes virtual environments, build outputs, git history, downloaded dependency sources, author photographs and manuscript files. Scripts that write into the surrounding manuscript directories, and the stale original packaging entry point, are omitted from the quick-use source tree. Existing analysis/plot scripts can require their original result layout, Python packages and TeX; the standard-library verifier is the supported entry point for checking the archived release data.

## Licenses and citation

Authored code, including the baseline reproductions and helper scripts, is provided under **MIT** ([LICENSE-CODE.txt](LICENSE-CODE.txt)). Data, sanitized measurement metadata and data documentation are under **CC BY 4.0** ([LICENSE-DATA.txt](LICENSE-DATA.txt)). Third-party libraries retain their upstream licenses; they are not relabeled as MIT by this package. See the dependency distributions for their complete notices. The two license scopes are also documented in `data/README.md`.

Use [CITATION.cff](CITATION.cff) for the five-author order and release version. No DOI or publication acceptance is claimed in this local release candidate.
