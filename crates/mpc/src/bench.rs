use crate::{
    arithmetic::*,
    backend::{self, Prepared, ProverOptions},
    fri_profile::FriProfile,
    protocol::{self, Algorithm, Fixtures, Layout, Params, ShaImplementation, Statement, Variant},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs, path::Path, time::Instant};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub statement: Statement,
    pub iteration: usize,
    pub proof_file: String,
    pub metrics: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub version: u32,
    pub scope: String,
    pub params: Params,
    pub repetitions: usize,
    pub warmups: usize,
    pub fri_profile: FriProfile,
    pub compact_public_openings: bool,
    pub records: Vec<Record>,
    pub metadata: Value,
}
#[derive(Clone, Copy)]
pub struct ExecutionOptions {
    pub prover: ProverOptions,
    pub verifier_cache: bool,
}

/// Measures the two-party proof workflow under the selected message policy.
pub fn benchmark_with_message_policy(
    dir: &Path,
    n: usize,
    repetitions: usize,
    warmups: usize,
    layouts: &[Layout],
    variants: &[Variant],
    sha_implementation: ShaImplementation,
    fri_profile: FriProfile,
    compact_public_openings: bool,
    fixtures_override: Option<&Fixtures>,
    execution: ExecutionOptions,
    message_policy: protocol::EncMessagePolicy,
) -> Result<(), String> {
    let prover_options = execution.prover;
    let verifier_cache = execution.verifier_cache;
    fri_profile.validate()?;
    if sha_implementation == ShaImplementation::NotUsed {
        return Err("benchmark requires the periodic SHA implementation".into());
    }
    if repetitions == 0 {
        return Err("repetitions must be positive".into());
    }
    if dir.join("run.json").exists() {
        return Err("output already contains run.json; choose a new directory".into());
    }
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    let binary_hash = hash(&fs::read(&binary).map_err(|e| e.to_string())?);
    let binary_sha256: String = binary_hash.iter().map(|b| format!("{b:02x}")).collect();
    let start = Instant::now();
    let mut rng = crate::private_rng();
    let params = Params::provisional(n)?;
    let local_fixtures;
    let fixtures = if let Some(fixtures) = fixtures_override {
        if fixtures.params != params {
            return Err("shared fixtures use different parameters".into());
        }
        fixtures
    } else {
        local_fixtures = Fixtures::generate_digit8(params.clone(), &mut rng)?;
        &local_fixtures
    };
    let mut run = Run {
        version: 3,
        scope: "two-party-workflow".into(),
        params,
        repetitions,
        warmups,
        fri_profile,
        compact_public_openings,
        records: vec![],
        metadata: json!({"profile":backend::PROFILE,"prover_options":prover_options,"verifier_cache":verifier_cache,
            "benchmark_binary_path":binary,"benchmark_binary_name":binary.file_name().and_then(|s|s.to_str()),"benchmark_binary_sha256":binary_sha256,
            "build":{"avx2":cfg!(target_feature="avx2"),"sha":cfg!(target_feature="sha"),"packing_width":<<F as p3_field::Field>::Packing as p3_field::PackedValue>::WIDTH},
            "plonky3_revision":crate::PLONKY3_REVISION,
            "fixture_generation_seconds":if fixtures_override.is_some(){None}else{Some(start.elapsed().as_secs_f64())},
            "fixture_source":if fixtures_override.is_some(){"shared in-memory fixtures; generation timed by tuning driver"}else{"generated in this benchmark"},
            "reference_decryption_matches_plaintext_sum":true,"same_fixtures_for_all_variants_and_layouts":true,"rayon_threads":std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_|"automatic".into()),"rng":"OS-seeded StdRng; fresh proof masks","lift":"explicit provisional digit lift","timing_unit":"seconds","size_unit":"bytes","verifier_setup":"public statement-dependent circuit preprocessing, reported separately and in cold total"}),
    };
    for &layout in layouts {
        for &variant in variants {
            for (mut statement, witness) in fixtures.statements(variant, layout) {
                if statement.algorithm == Algorithm::Enc {
                    statement.message_policy = message_policy;
                }
                if statement.key_hash.is_some() {
                    statement.sha_implementation = sha_implementation;
                }
                eprintln!(
                    "preparing {variant:?}/{layout:?}/{:?}/party{} N={n}",
                    statement.algorithm, statement.party
                );
                let start = Instant::now();
                let compiled = protocol::compile_trace(&statement, Some(&witness))?;
                let ntts = compiled.private_ntts;
                let sha_blocks = compiled.sha_blocks;
                let gates = compiled.operations;
                let (air, trace) = (compiled.air, compiled.trace);
                let trace_seconds = start.elapsed().as_secs_f64();
                let setup = Prepared::with_verifier_cache(
                    air,
                    statement.digest()?,
                    fri_profile,
                    prover_options,
                    verifier_cache,
                )?;
                eprintln!(
                    "  gates={gates} rows={} setup={:.3}s",
                    setup.air.rows, setup.setup_seconds
                );
                for iteration in 0..warmups + repetitions {
                    let start = Instant::now();
                    let proof = setup.prove(&trace)?;
                    let prove_seconds = start.elapsed().as_secs_f64();
                    let start = Instant::now();
                    let encoded = setup.encode(proof, compact_public_openings)?;
                    let bytes = encoded.bytes;
                    let serialization_seconds = start.elapsed().as_secs_f64();
                    let start = Instant::now();
                    let decoded = setup.decode(&bytes)?;
                    setup.verify(&decoded)?;
                    let verify_seconds = start.elapsed().as_secs_f64();
                    eprintln!(
                        "  iteration={iteration} prove={prove_seconds:.3}s verify={verify_seconds:.3}s bytes={}",
                        bytes.len()
                    );
                    if iteration < warmups {
                        continue;
                    }
                    let filename = format!(
                        "{:?}-{:?}-{:?}-p{}-r{}.proof",
                        variant,
                        layout,
                        statement.algorithm,
                        statement.party,
                        iteration - warmups
                    );
                    fs::write(dir.join(&filename), &bytes).map_err(|e| e.to_string())?;
                    let metrics = json!({"witness_trace_seconds":trace_seconds,"public_preprocessing_seconds":setup.setup_seconds,
                "prover_preprocessing_seconds":setup.setup_seconds,
                "prover_metadata_preprocessing_seconds":setup.verifier_metadata_seconds,
                "prover_core_seconds":prove_seconds,"proof_serialization_seconds":serialization_seconds,
                "prover_seconds":trace_seconds+prove_seconds+serialization_seconds,
                "prover_with_public_preprocessing_seconds":trace_seconds+setup.setup_seconds+prove_seconds+serialization_seconds,
                "proof_verification_seconds":verify_seconds,"verifier_online_seconds":verify_seconds,"proof_size_bytes":bytes.len(),"verified":true,
                "private_ntts":ntts,"ntt_butterflies":ntts*(n/2)*n.ilog2() as usize,
                "ntt_radix":setup.security["ntt_radix"],
                "ntt_radix4_rows":ntts*(n/4)*(n.ilog2() as usize/2)+if n.ilog2()%2==1 {ntts*n/2}else{0},"sha_compressions":sha_blocks,
                "native_sha_rows":setup.security["native_sha_rows"],
                "expanded_proof_size_bytes":encoded.expanded_size_bytes,
                "public_opening_saved_bytes":encoded.public_opening_saved_bytes,
                "security":setup.security});
                    run.records.push(Record {
                        statement: statement.clone(),
                        iteration: iteration - warmups,
                        proof_file: filename,
                        metrics,
                    });
                    fs::write(
                        dir.join("run.json"),
                        serde_json::to_vec_pretty(&run).unwrap(),
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        }
    }
    write_summary(dir, &run)?;
    Ok(())
}
/// Writes the measured run summary without private witnesses.
fn write_summary(dir: &Path, run: &Run) -> Result<(), String> {
    let mut csv = String::from(
        "variant,sha_implementation,layout,algorithm,party,iteration,prover_seconds,prover_core_seconds,witness_trace_seconds,prover_preprocessing_seconds,public_preprocessing_seconds,prover_with_public_preprocessing_seconds,verifier_frontend_seconds,verifier_preprocessing_seconds,verifier_public_setup_seconds,proof_verification_seconds,verifier_online_seconds,verifier_cold_seconds,proof_size_bytes,native_sha_rows,expanded_proof_size_bytes,public_opening_saved_bytes,prover_metadata_preprocessing_seconds,verifier_metadata_preprocessing_seconds\n",
    );
    for r in &run.records {
        let m = &r.metrics;
        let sha_implementation = format!("{:?}", r.statement.sha_implementation);
        let mut fields = vec![
            format!("{:?}", r.statement.variant),
            sha_implementation,
            format!("{:?}", r.statement.layout),
            format!("{:?}", r.statement.algorithm),
            r.statement.party.to_string(),
            r.iteration.to_string(),
        ];
        for name in [
            "prover_seconds",
            "prover_core_seconds",
            "witness_trace_seconds",
            "prover_preprocessing_seconds",
            "public_preprocessing_seconds",
            "prover_with_public_preprocessing_seconds",
            "verifier_frontend_seconds",
            "verifier_preprocessing_seconds",
            "verifier_public_setup_seconds",
            "proof_verification_seconds",
            "verifier_online_seconds",
            "verifier_cold_seconds",
            "proof_size_bytes",
            "native_sha_rows",
            "expanded_proof_size_bytes",
            "public_opening_saved_bytes",
            "prover_metadata_preprocessing_seconds",
            "verifier_metadata_preprocessing_seconds",
        ] {
            fields.push(
                m.get(name)
                    .filter(|value| !value.is_null())
                    .map_or(String::new(), Value::to_string),
            );
        }
        csv.push_str(&fields.join(","));
        csv.push('\n');
    }
    fs::write(dir.join("metrics.csv"), csv).map_err(|e| e.to_string())
}
/// Checks equality of two public polynomial vectors.
fn eq_poly(a: &[u64], b: &[u64]) -> Result<(), String> {
    if a != b {
        Err("public registry/ciphertext substitution".into())
    } else {
        Ok(())
    }
}

/// Validates registration, session, and ciphertext consistency across the workflow.
pub fn check_workflow(run: &Run) -> Result<(), String> {
    if run.version != 3 || run.repetitions == 0 {
        return Err("wrong run format".into());
    }
    run.params.validate()?;
    run.fri_profile.validate()?;
    if run.records.is_empty() {
        return Err("empty proof manifest".into());
    }
    let mut groups = vec![];
    for r in &run.records {
        r.statement.validate()?;
        if r.statement.params != run.params {
            return Err("mixed parameter profiles".into());
        }
        let key = (r.statement.variant, r.statement.layout);
        if !groups.contains(&key) {
            groups.push(key);
        }
    }
    if run.scope != "two-party-workflow" {
        return Err("unsupported run scope".into());
    }
    for (variant, layout) in groups {
        let records: Vec<_> = run
            .records
            .iter()
            .filter(|r| r.statement.variant == variant && r.statement.layout == layout)
            .collect();
        if records.len() != 6 * run.repetitions {
            return Err("incomplete workflow".into());
        }
        let get = |alg: Algorithm, party: u8| -> Result<&Statement, String> {
            let selected: Vec<_> = records
                .iter()
                .filter(|r| r.statement.algorithm == alg && r.statement.party == party)
                .collect();
            if selected.len() != run.repetitions {
                return Err("missing or duplicate component".into());
            }
            let first = &selected[0].statement;
            let digest = first.digest()?;
            for iteration in 0..run.repetitions {
                if selected.iter().filter(|r| r.iteration == iteration).count() != 1 {
                    return Err("missing/duplicate iteration".into());
                }
            }
            for r in selected {
                if r.statement.digest()? != digest {
                    return Err("repetitions changed the public workload".into());
                }
            }
            Ok(first)
        };
        let kg = [get(Algorithm::Keygen, 0)?, get(Algorithm::Keygen, 1)?];
        let enc = [get(Algorithm::Enc, 0)?, get(Algorithm::Enc, 1)?];
        if enc[0].message_policy != enc[1].message_policy {
            return Err("parties disagree on ENC message domain".into());
        }
        let dec = [get(Algorithm::Dec, 0)?, get(Algorithm::Dec, 1)?];
        eq_poly(&kg[0].a, &kg[1].a)?;
        let n = run.params.n;
        let b = encode(&add(&parse_poly(&kg[0].b, n)?, &parse_poly(&kg[1].b, n)?));
        let c0 = encode(&add(
            &parse_poly(&enc[0].c0, n)?,
            &parse_poly(&enc[1].c0, n)?,
        ));
        let c1 = encode(&add(
            &parse_poly(&enc[0].c1, n)?,
            &parse_poly(&enc[1].c1, n)?,
        ));
        let mut roster = b"VMPCKKS/v3/roster".to_vec();
        roster.extend(kg[0].key_id);
        for (i, s) in kg.iter().enumerate() {
            roster.push(i as u8);
            for &v in &s.b {
                roster.extend(v.to_le_bytes());
            }
            if let Some(t) = s.key_hash {
                roster.extend(t);
            }
        }
        let roster = hash(&roster);
        for s in kg.iter().chain(&enc).chain(&dec) {
            if s.key_id != kg[0].key_id || s.roster != roster {
                return Err("key id or registered roster mismatch".into());
            }
        }
        for pair in [&kg, &enc, &dec] {
            if pair[0].session != pair[1].session {
                return Err("parties disagree on session".into());
            }
        }
        if kg[0].session == enc[0].session
            || kg[0].session == dec[0].session
            || enc[0].session == dec[0].session
        {
            return Err("phase sessions must be distinct".into());
        }
        for i in 0..2 {
            eq_poly(&enc[i].a, &kg[0].a)?;
            eq_poly(&enc[i].b, &b)?;
            eq_poly(&dec[i].c0, &c0)?;
            eq_poly(&dec[i].c1, &c1)?;
            if variant == Variant::Pk {
                eq_poly(&dec[i].a, &kg[0].a)?;
                eq_poly(&dec[i].b, &kg[i].b)?;
            } else if dec[i].key_hash != kg[i].key_hash {
                return Err("unregistered key hash".into());
            }
            let mut request = b"VMPCKKS/v3/authorized-output".to_vec();
            request.extend(dec[i].key_id);
            request.extend(dec[i].session);
            for poly in [&c0, &c1] {
                for x in poly {
                    request.extend(x.to_le_bytes());
                }
            }
            if dec[i].authorized_request != hash(&request) {
                return Err("wrong authorized output digest".into());
            }
        }
    }
    Ok(())
}

/// Independently verifies every proof in the supplied public run manifest.
pub fn verify_run(dir: &Path) -> Result<(), String> {
    verify_run_with_message_policy(dir, None)
}

/// Verifies a run against an explicit application message policy.
pub fn verify_run_with_message_policy(
    dir: &Path,
    required: Option<protocol::EncMessagePolicy>,
) -> Result<(), String> {
    let mut run: Run =
        serde_json::from_slice(&fs::read(dir.join("run.json")).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    check_workflow(&run)?;
    if let Some(required) = required {
        let enc: Vec<_> = run
            .records
            .iter()
            .filter(|r| r.statement.algorithm == Algorithm::Enc)
            .collect();
        if enc.is_empty() || enc.iter().any(|r| r.statement.message_policy != required) {
            return Err(
                "manifest ENC domain does not match verifier-required message policy".into(),
            );
        }
    }

    let verifier_cache = run
        .metadata
        .get("verifier_cache")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let binary = std::env::current_exe().map_err(|e| e.to_string())?;
    run.metadata["verifier_build"] = json!({"avx2":cfg!(target_feature="avx2"),"sha":cfg!(target_feature="sha"),"packing_width":<<F as p3_field::Field>::Packing as p3_field::PackedValue>::WIDTH});
    run.metadata["verifier_binary_sha256"] = json!(
        hash(&fs::read(binary).map_err(|e| e.to_string())?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    let mut seen = vec![];
    for i in 0..run.records.len() {
        let context = run.records[i].statement.digest()?;
        if seen.contains(&context) {
            continue;
        }
        seen.push(context);
        let start = Instant::now();
        let compiled = protocol::compile_trace(&run.records[i].statement, None)?;
        let (air, _zero_trace) = (compiled.air, compiled.trace);
        let frontend_seconds = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let setup = Prepared::with_verifier_cache(
            air,
            context,
            run.fri_profile,
            ProverOptions::default(),
            verifier_cache,
        )?;
        let preprocessing_seconds = start.elapsed().as_secs_f64();
        let public_setup_seconds = frontend_seconds + preprocessing_seconds;
        for r in run
            .records
            .iter_mut()
            .filter(|r| r.statement.digest().ok() == Some(context))
        {
            if Path::new(&r.proof_file).components().count() != 1 {
                return Err("proof filename must be a single path component".into());
            }
            let bytes = fs::read(dir.join(&r.proof_file)).map_err(|e| e.to_string())?;
            let start = Instant::now();
            let proof = setup.decode(&bytes)?;
            setup.verify(&proof)?;
            let online = start.elapsed().as_secs_f64();
            r.metrics["verifier_frontend_seconds"] = json!(frontend_seconds);
            r.metrics["verifier_preprocessing_seconds"] = json!(preprocessing_seconds);
            r.metrics["verifier_metadata_preprocessing_seconds"] =
                json!(setup.verifier_metadata_seconds);
            r.metrics["proof_verification_seconds"] = json!(online);
            r.metrics["verifier_online_seconds"] = json!(online);
            r.metrics["verifier_public_setup_seconds"] = json!(public_setup_seconds);
            r.metrics["verifier_cold_seconds"] = json!(public_setup_seconds + online);
            r.metrics["independent_process_verified"] = json!(true);
            eprintln!(
                "verified {} frontend={frontend_seconds:.3}s preprocessing={preprocessing_seconds:.3}s proof={online:.6}s total={:.3}s",
                r.proof_file,
                public_setup_seconds + online
            );
        }
    }
    run.metadata["independent_verifier_completed"] = json!(true);
    run.metadata["verification_timing"] = json!({
        "frontend": "public circuit construction, public NTT and zero-placeholder trace allocation",
        "preprocessing": "public preprocessing commitment, backend security/setup and optional checked verifier metadata; metadata subphase is included, not added again",
        "proof_verification": "proof envelope decode, public opening reconstruction, proof shape checks and cryptographic verification",
        "total": "frontend + preprocessing + proof_verification; no amortization across repetitions",
        "excluded": "proof file I/O, workflow consistency checks and statement digest calculation",
        "cache_scope": "identical full public statement, backend profile and FRI profile; in-process only"
    });
    fs::write(
        dir.join("run.json"),
        serde_json::to_vec_pretty(&run).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    write_summary(dir, &run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    #[test]
    /// Rejects substituted registered keys and approved ciphertexts.
    fn registry_and_ciphertext_substitution_rejected() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(99);
        let f = Fixtures::generate(Params::provisional(16).unwrap(), &mut rng).unwrap();
        for v in [Variant::Sha, Variant::Pk] {
            let mut run = Run {
                version: 3,
                scope: "two-party-workflow".into(),
                params: f.params.clone(),
                repetitions: 1,
                warmups: 0,
                fri_profile: FriProfile::default(),
                compact_public_openings: true,
                records: f
                    .statements(v, Layout::for_variant(v))
                    .into_iter()
                    .map(|(statement, _)| Record {
                        statement,
                        iteration: 0,
                        proof_file: "test.proof".into(),
                        metrics: json!({}),
                    })
                    .collect(),
                metadata: json!({}),
            };
            check_workflow(&run).unwrap();
            run.records[4].statement.c0[0] ^= 1;
            assert!(check_workflow(&run).is_err());
            run.records[4].statement.c0[0] ^= 1;
            run.records[4].statement.key_id[0] ^= 1;
            assert!(check_workflow(&run).is_err());
            run.records[4].statement.key_id[0] ^= 1;
            if v == Variant::Sha {
                run.records[4].statement.key_hash.as_mut().unwrap()[0] ^= 1;
            } else {
                run.records[4].statement.b[0] ^= 1;
            }
            assert!(check_workflow(&run).is_err());
        }
    }
}
