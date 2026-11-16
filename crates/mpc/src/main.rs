use std::{collections::HashMap, env, path::Path};
use vmpckks::{
    backend::ProverOptions,
    bench,
    fri_profile::FriProfile,
    protocol::{EncMessagePolicy, Layout, ShaImplementation, Variant},
};
/// Dispatches current benchmark and independent verification commands.
fn main() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.get(1).is_some_and(|s| s == "verify-run") {
        let dir = Path::new(args.get(2).ok_or("missing run directory")?);
        if args.len() == 3 {
            return bench::verify_run(dir);
        }
        if args.len() == 5 && args[3] == "--require-message-policy" {
            let policy = match args[4].as_str() {
                "free" => EncMessagePolicy::Unrestricted,
                "digit8-quadratic" => EncMessagePolicy::Unsigned8Quadratic,
                _ => return Err("unknown message policy".into()),
            };
            return bench::verify_run_with_message_policy(dir, Some(policy));
        }
        return Err("invalid verify-run arguments".into());
    }
    if args.get(1).is_some_and(|s| s == "benchmark") {
        if (args.len() - 2) % 2 != 0 {
            return Err("every option needs a value".into());
        }
        let mut options = HashMap::new();
        for pair in args[2..].chunks_exact(2) {
            if ![
                "--n",
                "--out",
                "--variant",
                "--profile",
                "--repetitions",
                "--warmups",
            ]
            .contains(&pair[0].as_str())
                || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
            {
                return Err(format!("unknown/duplicate option {}", pair[0]));
            }
        }
        let get = |k, default| options.get(k).copied().unwrap_or(default);
        let variant = match get("--variant", "pk") {
            "sha" => Variant::Sha,
            "pk" => Variant::Pk,
            _ => return Err("variant must be sha or pk".into()),
        };
        let profile = match get("--profile", "b8") {
            "b8" => FriProfile::b8(),
            "b16" => FriProfile::b16(),
            _ => return Err("profile must be b8 or b16".into()),
        };
        return bench::benchmark_with_message_policy(
            Path::new(get("--out", "artifacts/benchmark")),
            get("--n", "4096")
                .parse::<usize>()
                .map_err(|e| e.to_string())?,
            get("--repetitions", "10")
                .parse::<usize>()
                .map_err(|e| e.to_string())?,
            get("--warmups", "1")
                .parse::<usize>()
                .map_err(|e| e.to_string())?,
            &[Layout::for_variant(variant)],
            &[variant],
            ShaImplementation::OfficialPeriodic,
            profile,
            true,
            None,
            bench::ExecutionOptions {
                prover: ProverOptions::default(),
                verifier_cache: true,
            },
            if variant == Variant::Pk {
                EncMessagePolicy::Unsigned8Quadratic
            } else {
                EncMessagePolicy::Unrestricted
            },
        );
    }
    Err("usage: vmpckks benchmark --out DIR [--variant pk|sha --profile b8|b16 --n 4096 --repetitions 10 --warmups 1] | verify-run DIR [--require-message-policy digit8-quadratic|free]".into())
}
