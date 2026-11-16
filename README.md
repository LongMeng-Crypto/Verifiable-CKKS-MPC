# Verifiable CKKS MPC

Research implementation of two-party CKKS KeyGen, encryption, and decryption
relations using a hiding Plonky3 STARK. The retained implementations are:

- **V1:** periodic compilation of the official SHA-256 constraints, with fused
  radix-4 arithmetic and a complete salted hash binding the secret key.
- **V2:** fused radix-4 arithmetic, repeated registered-PK opening in decryption,
  and quadratic constraints proving that every message coefficient is in `0..7`.

Both support B8/Q100 and B16/Q75, maximum FRI folding arity 8, final polynomial
length 64, cubic Goldilocks challenges, and full SHA-256 Merkle/transcript hashing.
The actual AIR is checked for proven RBR >=128 bits and non-hash LDR >=144 bits
under the pinned upstream analysis. These are classical per-instance bounds;
the retained Fiat-Shamir and PK short-opening assumptions still apply.

## Build and test

Requirements: Linux or WSL2, Rust/Cargo 1.96.0 or newer, Git, Python 3, and GNU
`time` (`/usr/bin/time`). Run commands from the project root containing `Cargo.toml`.

```bash
bash scripts/bootstrap_backend.sh
RAYON_NUM_THREADS=4 RUST_TEST_THREADS=1 \
  python3 scripts/memory_guard.py -- bash scripts/test_mpc.sh
```

Bootstrap fetches Plonky3 revision
`0d803737b681774186cd283b1fd2d8e493655c82`, applies the four exact patches in
`dependencies/`, and checks its lockfile and complete tracked diff. The compiler
and periodic-plan artifacts are included in `crates/mpc/src/sha_frozen/`.
No other FHE project, private document, pre-existing build directory, or private
fixture is required. The development guard uses an 8 GiB budget and reserves
8 GiB of available RAM; it combines a per-process address-space cap with
process-group RSS polling, not a kernel aggregate RSS hard limit.

## Benchmark

```bash
# V2 at B8 and B16: N4096, 10 repetitions per party, one warmup
bash scripts/benchmark_message_range.sh

# Both retained variants at B8 and B16: three repetitions per party
bash scripts/benchmark_best.sh
```

Each script builds the native binaries once and runs cases sequentially with
8 Rayon workers, parallel private salts, public DFT caching, and verifier metadata
caching. Each case is verified by a fresh process. Choose one command for the
experiment you want; defaults create a new timestamped output directory.

The general entry point accepts output directory, N, repetitions, warmups, and
variant (`sha`, `pk`, or `both`), in that order:

```bash
bash scripts/benchmark.sh artifacts/my-v2-run 4096 10 1 pk
bash scripts/benchmark.sh artifacts/my-v1-v2-run 4096 3 1 both
```

Use a new output directory. If Cargo dependencies are not cached, prefix the
benchmark command with `CARGO_NET_OFFLINE=false`. Reports are written as
`comparison.md/csv/json`, per-case `summary.md/json`, raw metrics, resource logs,
public manifests, and binary proof files under `artifacts/`. Witnesses and fixture
seeds are never written to these reports.

To recheck a V2 case while explicitly requiring its message-range policy:

```bash
./target/probe-native/release/vmpckks verify-run PATH_TO_V2_CASE \
  --require-message-policy digit8-quadratic
```

## Reference measurements

The following historical measurements were collected on November 12, 2026,
before this source cleanup. They describe the retained circuits, not a new
benchmark of the cleanup. Each row reports one proof's mean; preprocessing is
separate. Prover time includes trace construction, proving, and serialization.
Proof verification includes envelope decoding and public-opening reconstruction.
One KiB is 1024 bytes.

### V2 fused arithmetic with quadratic message range

N4096; 20 samples per row after one warmup per statement.

| Profile | Proof | Prover (s) | Prover Preprocessing (s) | Verifier Public Preprocessing (s) | Proof Verification (ms) | Proof Size (KiB) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| B8 | KeyGen | 0.4895 | 0.0697 | 0.0649 | 1.964 | 375.5 |
| B8 | Encryption | 0.4080 | 0.0681 | 0.0676 | 1.982 | 374.9 |
| B8 | Decryption | 0.4518 | 0.0613 | 0.0688 | 1.993 | 384.2 |
| B16 | KeyGen | 0.8744 | 0.1231 | 0.1401 | 1.808 | 309.7 |
| B16 | Encryption | 0.8788 | 0.1198 | 0.1436 | 1.572 | 309.3 |
| B16 | Decryption | 0.9359 | 0.1183 | 0.1529 | 1.787 | 316.6 |

Cold verification additionally includes public frontend construction and public
preprocessing: approximately 74-77 ms for B8 and 150-161 ms for B16. B8 favors
prover speed; B16 favors smaller proofs.

### V1 periodic SHA with fused arithmetic

N4096; six samples per row after one warmup per statement. V1 does not include
V2's message-range policy. Its historical fixtures used messages in `0..3`, while
the V2 table used `0..7`; new scripts use shared `0..7` fixtures across profiles
and variants. Periodic V1 is retained for its lower setup cost and memory use;
the removed narrow72 control had slightly faster KG/DEC proving without setup.

| Profile | Proof | Prover (s) | Prover Preprocessing (s) | Verifier Public Preprocessing (s) | Proof Verification (ms) | Proof Size (KiB) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| B8 | KeyGen | 1.1214 | 0.0920 | 0.0996 | 3.310 | 499.4 |
| B8 | Encryption | 0.4141 | 0.0625 | 0.0710 | 2.107 | 376.6 |
| B8 | Decryption | 1.1450 | 0.0910 | 0.0978 | 2.961 | 505.4 |
| B16 | KeyGen | 1.8264 | 0.1601 | 0.1739 | 2.419 | 403.9 |
| B16 | Encryption | 0.8613 | 0.1228 | 0.1267 | 1.555 | 308.3 |
| B16 | Decryption | 1.8994 | 0.1574 | 0.1708 | 2.375 | 406.8 |

### Benchmark machine

| Parameter | Configuration |
| --- | --- |
| CPU | Intel Core i9-14900, x86-64 |
| Environment | WSL2, Linux 6.6.87.2 |
| Parallelism | 8 Rayon worker threads |
| Compiler | Rust 1.96.0, release, `-C target-cpu=native` |
| SIMD | AVX2; Goldilocks packing width = 4 |

## Parameters and proved relations

The ring is `F_q[X]/(X^4096+1)` with
`q=18446744069414584321` (Goldilocks). Each party's secret is sparse ternary
with exact Hamming weight 256; encryption randomness is ternary without a fixed
weight. Small errors are bounded by 26, and each decryption flooding share is
bounded by `366857376337484500`.

For a registered party key `b_i`, collective key `b`, and approved ciphertext
`(C0,C1)`, the arithmetic relations are:

```text
KeyGen:      b_i = -a*s_i + e_i
Encryption:  c0_i = b*u_i + e0_i + kappa*m_i
             c1_i = a*u_i + e1_i
Decryption:  d_i = C1*s_i + r_i
```

V2 decryption also reopens the same enrolled PK equation with the same `s_i` and
checks its Hamming weight and error bounds. V1 keygen/decryption bind `s_i` through
one complete salted SHA-256 message, including IV, padding, all 17 compression
blocks at N4096, final digest, and authenticated arithmetic-secret reads.

The current reference evaluation is ciphertext addition. The lift is explicitly
**provisional**: `kappa=(q-1)/8=2305843008676823040`. Message coefficients are
digits, not a completed CKKS slot encoder or a confirmed CKKS engine adapter.
The circuits prove error ranges, not honest sampling distributions. This demo
does not implement collaborative noise sampling, a noise commitment, a complete
simulation-based MPC security theorem, or a proof of general FHE evaluation.

## Validation of the cleanup

The retained implementation passes 36 application tests, including real N4096
proofs for both variants and profiles, exact reconstruction of all 8096 official
SHA constraints, and adversarial range, copy, chaining, policy, and context tests.
The four-case N16 CLI smoke independently verifies 24 proofs. The cleaned verifier
also accepts all 156 archived proofs from the retained fastest V1/V2 profiles,
without changing their original manifests or proof files. Development checks use
four Rayon workers; the observed full-suite peak is approximately 3.24 GiB.
These checks are correctness evidence, not new eight-thread performance results.

## Adding single-limb bootstrapping

The bootstrapping computation can be shared by V1 and V2: these variants differ
in secret-key binding, not in the ring/ciphertext arithmetic. A V2-only proof
extension can be developed first without duplicating the computational engine.
There is currently no bootstrapping implementation or bootstrapping-key generator.

| File or new module | Integration work |
| --- | --- |
| `crates/mpc/src/arithmetic.rs` | Reuse ring arithmetic and NTTs; introduce the required encoding, scale, rounding, and decoding conventions. |
| New `crates/mpc/src/bootstrap.rs` | Implement the single-limb bootstrap or refresh engine and time its key setup, evaluation, and memory independently. |
| `crates/mpc/src/protocol.rs` | Define explicit bootstrap parameters, evaluation-key/public-input types, and input/output bindings; extend the currently frozen parameter validation deliberately. |
| `crates/mpc/src/bench.rs` | Insert bootstrapping into the reference workflow and add phase metrics. Update `check_workflow`, which currently requires the approved ciphertext to equal the sum of the two ENC ciphertexts. |
| `crates/mpc/src/bin/vmpckks-prover-bench.rs` | Add controlled before/after bootstrapping cases and independent verification. |
| `crates/mpc/src/specialized.rs` and `circuit.rs` | Add bootstrap constraints and authenticated wire connections only if bootstrapping correctness itself must be proved. |
| `crates/mpc/src/backend.rs` and `fri_profile.rs` | Recount security and hiding/opening budgets for any new proof AIR. |

First settle whether the desired operation is server-side homomorphic CKKS
bootstrapping using evaluation keys, or interactive threshold decrypt/re-encrypt
refresh. These are different protocols. The current digit-lift demo does not
supply the CKKS encoding, scale/noise schedule, approximate modular reduction,
or evaluation keys required by a complete CKKS bootstrap. Any necessary change
to q, N, distributions, or encoding needs an explicit new parameter profile and
correctness/security analysis; the existing benchmark numbers do not cover it.

A computation-only benchmark can reuse the current KG/ENC/DEC proofs while
measuring bootstrapping separately, but that does not prove the intermediate
bootstrapping step. To make server evaluation verifiable, add a dedicated
input-to-output relation and bind it into the workflow instead of bypassing the
existing ciphertext checks. Bootstrap keys must be tied to the enrolled key;
revealing a secret key to the server is not a bootstrap-key interface.

For an initial V2-only proof integration, preserve the registered-PK opening in
DEC and implement the new bootstrap relation beside it. V1's periodic SHA module
and generated polynomial evaluator need no changes unless secret-key binding or
its authenticated encoding changes.
