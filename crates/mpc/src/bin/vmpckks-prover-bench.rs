use rand::{RngExt, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use vmpckks::{
    arithmetic::hash,
    backend::ProverOptions,
    bench::{self, Run},
    fri_profile::FriProfile,
    protocol::{Algorithm, EncMessagePolicy, Fixtures, Layout, Params, ShaImplementation, Variant},
};

const METRICS: &[&str] = &[
    "proof_size_bytes",
    "expanded_proof_size_bytes",
    "public_opening_saved_bytes",
    "witness_trace_seconds",
    "prover_preprocessing_seconds",
    "prover_core_seconds",
    "proof_serialization_seconds",
    "prover_seconds",
    "prover_with_public_preprocessing_seconds",
    "verifier_frontend_seconds",
    "verifier_preprocessing_seconds",
    "prover_metadata_preprocessing_seconds",
    "verifier_metadata_preprocessing_seconds",
    "proof_verification_seconds",
    "verifier_cold_seconds",
];

#[derive(Clone, Serialize, Deserialize)]
struct Case {
    name: String,
    phase: String,
    native: bool,
    variant: Variant,
    verifier_cache: bool,
    #[serde(default)]
    message_policy: EncMessagePolicy,
    layout: Layout,
    options: ProverOptions,
    fri: FriProfile,
    repetitions: usize,
    warmups: usize,
}
#[derive(Serialize)]
struct Stats {
    mean: f64,
    median: f64,
    minimum: f64,
    maximum: f64,
    sample_stdev: Option<f64>,
}
#[derive(Serialize)]
struct Component {
    samples: usize,
    metrics: BTreeMap<String, Stats>,
    security: Value,
}
#[derive(Serialize)]
struct Outcome {
    case: Case,
    components: BTreeMap<String, Component>,
    directory: String,
}
#[derive(Serialize)]
struct Report {
    version: u32,
    n: usize,
    suite: String,
    verifier_native: bool,
    fixture_scope: String,
    shared_fixture_id: Option<String>,
    selection: String,
    rayon_threads: String,
    outcomes: Vec<Outcome>,
}

/// Encodes bytes as lowercase hexadecimal.
fn hex(x: &[u8]) -> String {
    x.iter().map(|b| format!("{b:02x}")).collect()
}
/// Converts an error into a diagnostic string.
fn error(e: impl std::fmt::Display) -> String {
    e.to_string()
}
/// Constructs the selected B8 or B16 FRI profile.
fn profile(blowup: usize, queries: usize) -> FriProfile {
    FriProfile {
        log_blowup: blowup.ilog2() as usize,
        num_queries: queries,
        max_log_arity: 3,
        log_final_poly_len: 6,
    }
}
/// Selects the current V1 and V2 B8/B16 benchmark cases.
fn cases(repetitions: usize, warmups: usize, variant: &str) -> Vec<Case> {
    let variants = match variant {
        "sha" => vec![Variant::Sha],
        "pk" => vec![Variant::Pk],
        _ => vec![Variant::Sha, Variant::Pk],
    };
    variants
        .into_iter()
        .flat_map(|variant| {
            [(16, 75), (8, 100)]
                .into_iter()
                .map(move |(blowup, queries)| Case {
                    name: format!(
                        "{}-b{blowup}",
                        if variant == Variant::Sha {
                            "v1-periodic-fused"
                        } else {
                            "v2-digit8-quadratic"
                        }
                    ),
                    phase: "final".into(),
                    native: cfg!(target_feature = "avx2"),
                    variant,
                    verifier_cache: true,
                    message_policy: if variant == Variant::Pk {
                        EncMessagePolicy::Unsigned8Quadratic
                    } else {
                        EncMessagePolicy::Unrestricted
                    },
                    layout: Layout::for_variant(variant),
                    options: ProverOptions::default(),
                    fri: profile(blowup, queries),
                    repetitions,
                    warmups,
                })
        })
        .collect()
}
impl Case {
    /// Returns the retained periodic SHA implementation.
    fn sha_implementation(&self) -> ShaImplementation {
        ShaImplementation::OfficialPeriodic
    }
}
/// Writes separate proof-component statistics in Markdown, CSV, and JSON.
fn write_report(dir: &Path, r: &Report) -> Result<(), String> {
    let title = "Current V1/V2 B8/B16";
    let method = "Shared full-digit8 fixtures; V1 periodic/fused and V2 fused with quadratic message range. B8/Q100 and B16/Q75, fold8/final64; native/cache-on throughout. Each actual AIR passes RBR128/LDR144.";
    let mut md = format!(
        "# {title} benchmark\n\nN={}; Rayon threads={}. {}\n\n{method} Every row is one KG/ENC/DEC proof's mean, never a sum across components. Prover time includes trace, proving and serialization; prover preprocessing is separate. Verifier frontend/public preprocessing are separate from proof verification, which includes public opening reconstruction.\n\n| Case | Phase | Proof | Samples | Size KiB | Prover s | Prover preprocessing s | Prover core s |\n| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |\n",
        r.n, r.rayon_threads, r.fixture_scope
    );
    let mut csv = "case,phase,proof,samples".to_string();
    for key in METRICS {
        csv.push(',');
        csv.push_str(key);
    }
    csv.push_str(",proven_rbr_bits,ldr_non_hash_bits\n");
    for o in &r.outcomes {
        for (key, label) in [("Keygen", "KG"), ("Enc", "ENC"), ("Dec", "DEC")] {
            let c = &o.components[key];
            let v = &c.metrics;
            md.push_str(&format!(
                "| {} | {} | {} | {} | {:.1} | {:.4} | {:.4} | {:.4} |\n",
                o.case.name,
                o.case.phase,
                label,
                c.samples,
                v["proof_size_bytes"].mean / 1024.,
                v["prover_seconds"].mean,
                v["prover_preprocessing_seconds"].mean,
                v["prover_core_seconds"].mean
            ));
            csv.push_str(&format!(
                "{},{},{},{}",
                o.case.name, o.case.phase, label, c.samples
            ));
            for metric in METRICS {
                csv.push_str(&format!(",{}", v[*metric].mean));
            }
            csv.push_str(&format!(
                ",{},{}\n",
                c.security["proven_rbr_bits"], c.security["ldr_non_hash_bits"]
            ));
        }
    }
    md.push_str("\n| Case | Proof | Verifier frontend s | Public preprocessing s | Metadata prep ms (included) | Proof verification ms | Cold verifier s | RBR bits | LDR non-hash bits |\n| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
    for o in &r.outcomes {
        for (key, label) in [("Keygen", "KG"), ("Enc", "ENC"), ("Dec", "DEC")] {
            let c = &o.components[key];
            let v = &c.metrics;
            md.push_str(&format!(
                "| {} | {} | {:.4} | {:.4} | {:.3} | {:.3} | {:.4} | {} | {:.3} |\n",
                o.case.name,
                label,
                v["verifier_frontend_seconds"].mean,
                v["verifier_preprocessing_seconds"].mean,
                1000. * v["verifier_metadata_preprocessing_seconds"].mean,
                1000. * v["proof_verification_seconds"].mean,
                v["verifier_cold_seconds"].mean,
                c.security["proven_rbr_bits"],
                c.security["ldr_non_hash_bits"].as_f64().unwrap()
            ));
        }
    }
    let verifier_cpu = if r.verifier_native {
        "native"
    } else {
        "portable"
    };
    md.push_str(&format!("\nPublic setup is charged in full to each corresponding proof measurement, without amortization. All cases generate fresh proof masks. Each case is independently verified by a fresh {verifier_cpu} process. Proof I/O, workflow checks and statement digest calculation are outside phase timers. Proof wire bytes include the envelope; known public application statements and preprocessing storage are separate. JSON records samples, spread, build metadata and actual binary hashes.\n"));
    for (name, bytes) in [
        (
            "comparison.json",
            serde_json::to_vec_pretty(r).map_err(error)?,
        ),
        ("comparison.csv", csv.into_bytes()),
        ("comparison.md", md.into_bytes()),
    ] {
        fs::write(dir.join(name), bytes).map_err(error)?;
    }
    Ok(())
}
/// Runs a measured child process with an optional private fixture seed.
fn run_child(
    exe: &Path,
    args: &[String],
    seed: Option<&[u8; 32]>,
    dir: &Path,
    phase: &str,
) -> Result<(), String> {
    let log = fs::File::create(dir.join(format!("{phase}.log"))).map_err(error)?;
    let mut command = Command::new("/usr/bin/time");
    command
        .args(["-v", "-o"])
        .arg(dir.join(format!("{phase}-resources.txt")))
        .arg(exe)
        .args(args)
        .stdout(Stdio::null())
        .stderr(log)
        .stdin(if seed.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.spawn().map_err(error)?;
    if let Some(seed) = seed {
        let mut input = child.stdin.take().ok_or("missing private pipe")?;
        input.write_all(seed).map_err(error)?;
        drop(input);
    }
    let status = child.wait().map_err(error)?;
    if !status.success() {
        return Err(format!(
            "{phase} failed in {}: {status}; inspect {phase}.log",
            dir.display()
        ));
    }
    Ok(())
}
/// Returns the unique public statements used by a benchmark case.
fn normalized_workload(run: &Run) -> Result<Value, String> {
    let statements: BTreeMap<_, _> = run
        .records
        .iter()
        .map(|r| {
            (
                format!("{:?}-{}", r.statement.algorithm, r.statement.party),
                &r.statement,
            )
        })
        .collect();
    serde_json::to_value(statements).map_err(error)
}
/// Validates and aggregates independently verified component measurements.
fn aggregate(run: &Run, dir: &Path) -> Result<BTreeMap<String, Component>, String> {
    if run.records.len() != 6 * run.repetitions
        || run.metadata["independent_verifier_completed"] != true
    {
        return Err("incomplete independent two-party verification".into());
    }
    let mut components = BTreeMap::new();
    for key in ["Keygen", "Enc", "Dec"] {
        let records: Vec<_> = run
            .records
            .iter()
            .filter(|r| format!("{:?}", r.statement.algorithm) == key)
            .collect();
        if records.len() != 2 * run.repetitions {
            return Err(format!("missing {key} samples"));
        }
        for r in &records {
            let m = &r.metrics;
            if m["independent_process_verified"] != true
                || m["verified"] != true
                || m["security"]["proven_rbr_bits"].as_f64().unwrap_or(0.) < 128.
                || m["security"]["ldr_non_hash_bits"].as_f64().unwrap_or(0.) < 144.
                || fs::metadata(dir.join(&r.proof_file)).map_err(error)?.len()
                    != m["proof_size_bytes"].as_u64().unwrap_or(0)
            {
                return Err(format!(
                    "invalid size/verification/security in {}",
                    r.proof_file
                ));
            }
        }
        let mut metrics = BTreeMap::new();
        for name in METRICS {
            let values: Vec<_> = records
                .iter()
                .map(|r| {
                    r.metrics[*name]
                        .as_f64()
                        .filter(|v| v.is_finite() && *v >= 0.)
                        .ok_or_else(|| format!("invalid metric {name}"))
                })
                .collect::<Result<_, _>>()?;
            let mean = values.iter().sum::<f64>() / values.len() as f64;
            let mut sorted = values.clone();
            sorted.sort_by(f64::total_cmp);
            let median = (sorted[(sorted.len() - 1) / 2] + sorted[sorted.len() / 2]) / 2.;
            metrics.insert(
                (*name).into(),
                Stats {
                    mean,
                    median,
                    minimum: values.iter().copied().fold(f64::INFINITY, f64::min),
                    maximum: values.iter().copied().fold(0., f64::max),
                    sample_stdev: (values.len() > 1).then(|| {
                        (values.iter().map(|v| (v - mean).powi(2)).sum::<f64>()
                            / (values.len() - 1) as f64)
                            .sqrt()
                    }),
                },
            );
        }
        components.insert(
            key.into(),
            Component {
                samples: records.len(),
                metrics,
                security: records[0].metrics["security"].clone(),
            },
        );
    }
    Ok(components)
}
/// Runs isolated current V1/V2 benchmarks with shared private fixtures.
fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.get(1).is_some_and(|s| s == "__verify-run") {
        let policy =
            serde_json::from_str(args.get(3).ok_or("missing message policy")?).map_err(error)?;
        return bench::verify_run_with_message_policy(
            Path::new(args.get(2).ok_or("missing directory")?),
            Some(policy),
        );
    }
    if args.get(1).is_some_and(|s| s == "__case") {
        let case: Case = serde_json::from_str(args.get(2).ok_or("missing case")?).map_err(error)?;
        let dir = Path::new(args.get(3).ok_or("missing directory")?);
        let n = args.get(4).ok_or("missing N")?.parse().map_err(error)?;
        let mut seed = [0u8; 32];
        std::io::stdin().read_exact(&mut seed).map_err(error)?;
        let fixtures =
            Fixtures::generate_digit8(Params::provisional(n)?, &mut StdRng::from_seed(seed))?;
        bench::benchmark_with_message_policy(
            dir,
            n,
            case.repetitions,
            case.warmups,
            &[case.layout],
            &[case.variant],
            case.sha_implementation(),
            case.fri,
            true,
            Some(&fixtures),
            bench::ExecutionOptions {
                prover: case.options,
                verifier_cache: case.verifier_cache,
            },
            case.message_policy,
        )?;
        let path = dir.join("run.json");
        let mut run: Run =
            serde_json::from_slice(&fs::read(&path).map_err(error)?).map_err(error)?;
        run.metadata["shared_fixture_id"] = json!(hex(&hash(&fixtures.key_id)));
        run.metadata["benchmark_driver"] = json!("vmpckks-prover-bench");
        run.metadata["phase"] = json!("final");
        return fs::write(path, serde_json::to_vec_pretty(&run).map_err(error)?).map_err(error);
    }
    if args.get(1).is_some_and(|s| s == "--help") {
        println!(
            "vmpckks-prover-bench --out DIR [--variant sha|pk|both --n 4096 --repetitions 10 --warmups 1]"
        );
        return Ok(());
    }
    if (args.len() - 1) % 2 != 0 {
        return Err("every option needs a value".into());
    }
    let mut options = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        if !["--out", "--variant", "--n", "--repetitions", "--warmups"].contains(&pair[0].as_str())
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(format!("unknown/duplicate option {}", pair[0]));
        }
    }
    let out = PathBuf::from(*options.get("--out").ok_or("--out is required")?);
    let variant = *options.get("--variant").unwrap_or(&"both");
    if !["sha", "pk", "both"].contains(&variant) {
        return Err("variant must be sha/pk/both".into());
    }
    let n = options
        .get("--n")
        .unwrap_or(&"4096")
        .parse()
        .map_err(error)?;
    let repetitions = options
        .get("--repetitions")
        .unwrap_or(&"10")
        .parse()
        .map_err(error)?;
    let warmups = options
        .get("--warmups")
        .unwrap_or(&"1")
        .parse()
        .map_err(error)?;
    Params::provisional(n)?;
    if repetitions == 0 {
        return Err("repetitions must be positive".into());
    }
    if out.join("comparison.json").exists() {
        return Err("output already contains comparison.json".into());
    }
    fs::create_dir_all(&out).map_err(error)?;
    let out = fs::canonicalize(out).map_err(error)?;
    let native = env::current_exe().map_err(error)?;
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    env::set_current_dir(workspace).map_err(error)?;
    let seed: [u8; 32] = vmpckks::private_rng().random();
    let mut report = Report {
        version: 3,
        n,
        suite: "current".into(),
        verifier_native: cfg!(target_feature = "avx2"),
        fixture_scope:
            "Shared full-digit8 fixtures passed through private stdin; fresh proof masks.".into(),
        shared_fixture_id: None,
        selection: format!("current {variant} B8/B16"),
        rayon_threads: env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "automatic".into()),
        outcomes: vec![],
    };
    let mut expected = BTreeMap::<String, Value>::new();
    for case in cases(repetitions, warmups, variant) {
        let dir = out.join(&case.name);
        fs::create_dir_all(&dir).map_err(error)?;
        eprintln!("CASE {}", case.name);
        run_child(
            &native,
            &[
                "__case".into(),
                serde_json::to_string(&case).map_err(error)?,
                dir.display().to_string(),
                n.to_string(),
            ],
            Some(&seed),
            &dir,
            "prover",
        )?;
        run_child(
            &native,
            &[
                "__verify-run".into(),
                dir.display().to_string(),
                serde_json::to_string(&case.message_policy).map_err(error)?,
            ],
            None,
            &dir,
            "verifier",
        )?;
        let run: Run = serde_json::from_slice(&fs::read(dir.join("run.json")).map_err(error)?)
            .map_err(error)?;
        if run.fri_profile != case.fri
            || run.repetitions != case.repetitions
            || run.warmups != case.warmups
            || run.records.iter().any(|r| {
                r.statement.layout != case.layout
                    || r.statement.variant != case.variant
                    || r.statement.message_policy
                        != if r.statement.algorithm == Algorithm::Enc {
                            case.message_policy
                        } else {
                            EncMessagePolicy::Unrestricted
                        }
                    || r.statement.sha_implementation
                        != if r.statement.key_hash.is_some() {
                            ShaImplementation::OfficialPeriodic
                        } else {
                            ShaImplementation::NotUsed
                        }
            })
        {
            return Err("actual statement differs from selected case".into());
        }
        let build = json!({"avx2":cfg!(target_feature="avx2"),"sha":cfg!(target_feature="sha"),"packing_width":<<vmpckks::arithmetic::F as p3_field::Field>::Packing as p3_field::PackedValue>::WIDTH});
        if run.metadata["build"] != build
            || run.metadata["verifier_build"] != build
            || run.metadata["verifier_cache"] != true
        {
            return Err("build/cache configuration mismatch".into());
        }
        let id = run.metadata["shared_fixture_id"]
            .as_str()
            .ok_or("missing fixture ID")?
            .to_string();
        if let Some(prior) = &report.shared_fixture_id {
            if prior != &id {
                return Err("fixture ID mismatch".into());
            }
        } else {
            report.shared_fixture_id = Some(id);
        }
        let workload = normalized_workload(&run)?;
        let key = format!("{:?}", case.variant);
        if let Some(prior) = expected.get(&key) {
            if prior != &workload {
                return Err("public workload changed across profiles".into());
            }
        } else {
            expected.insert(key, workload);
        }
        let status = Command::new("python3")
            .arg(workspace.join("scripts/summarize_benchmark.py"))
            .arg(&dir)
            .stdout(Stdio::null())
            .status()
            .map_err(error)?;
        if !status.success() {
            return Err("summary failed".into());
        }
        let components = aggregate(&run, &dir)?;
        for key in ["Keygen", "Enc", "Dec"] {
            let m = &components[key].metrics;
            eprintln!(
                "PASS {} {}: prover {:.4}s, verification {:.3}ms, proof {:.1}KiB",
                case.name,
                key,
                m["prover_seconds"].mean,
                1000. * m["proof_verification_seconds"].mean,
                m["proof_size_bytes"].mean / 1024.
            );
        }
        report.outcomes.push(Outcome {
            case,
            components,
            directory: dir.display().to_string(),
        });
        write_report(&out, &report)?;
    }
    Ok(())
}
