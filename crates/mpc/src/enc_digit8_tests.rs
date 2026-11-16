use crate::{
    arithmetic::{self, F, Q, encode, parse_poly},
    backend::{Prepared, preflight_security},
    fri_profile::FriProfile,
    protocol::{
        Algorithm, EncMessagePolicy, Fixtures, Layout, Params, Statement, Variant, Witness,
    },
    specialized::compile_trace,
};
use p3_air::BaseAir;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use rand::{SeedableRng, rngs::StdRng};

/// Constructs a deterministic valid fixture for the current proof relation.
fn fixture(n: usize) -> (Statement, Witness) {
    let f = Fixtures::generate_digit8(
        Params::provisional(n).unwrap(),
        &mut StdRng::seed_from_u64(2026111301),
    )
    .unwrap();
    let (mut s, w) = f
        .statements(Variant::Pk, Layout::SpecializedRadix4Fused)
        .into_iter()
        .find(|(s, _)| s.algorithm == Algorithm::Enc && s.party == 0)
        .unwrap();
    s.message_policy = EncMessagePolicy::Unsigned8Quadratic;
    (s, w)
}
/// Recomputes ciphertext coefficients from the supplied witness.
fn ciphertext(s: &mut Statement, w: &Witness) {
    let n = s.params.n;
    let (c0, c1) = arithmetic::enc(
        &parse_poly(&s.a, n).unwrap(),
        &parse_poly(&s.b, n).unwrap(),
        &w.secret,
        &w.e0,
        &w.e1,
        &w.message,
        F::from_u64(s.params.kappa),
    );
    s.c0 = encode(&c0);
    s.c1 = encode(&c1);
}
/// Constructs the selected B8 or B16 FRI profile.
fn profile(b: usize) -> FriProfile {
    FriProfile {
        log_blowup: b.ilog2() as usize,
        num_queries: if b == 8 { 100 } else { 75 },
        max_log_arity: 3,
        log_final_poly_len: 6,
    }
}
/// Locates the authenticated plaintext-combination row.
fn message_row(c: &crate::protocol::CompiledTrace) -> usize {
    c.air
        .specialized
        .as_ref()
        .unwrap()
        .preprocessed_trace()
        .unwrap()
        .values
        .chunks_exact(34)
        .position(|p| p[20] == F::ONE)
        .unwrap()
}
#[test]
/// Checks that the message constraints accept exactly the eight unsigned digits.
fn digit8_quadratic_has_exact_field_roots_and_unique_bits() {
    for x in (0u64..16).chain([Q - 1, Q - 2, Q - 7, Q / 2]) {
        let mut accepted = 0;
        for b1 in 0..2 {
            for b2 in 0..2 {
                let b0 = F::from_u64(x) - F::from_u8(2 * b1 + 4 * b2);
                accepted += usize::from(b0 * (b0 - F::ONE) == F::ZERO);
            }
        }
        assert_eq!(accepted, usize::from(x < 8), "x={x}");
    }
}
#[test]
/// Checks authenticated message policies and unrestricted statement encoding.
fn digit8_policy_authentication_and_legacy_statement_compatibility() {
    let (bounded, _) = fixture(16);
    let mut free = bounded.clone();
    free.message_policy = EncMessagePolicy::Unrestricted;
    let json = serde_json::to_value(&free).unwrap();
    assert!(json.get("message_policy").is_none());
    let decoded: Statement = serde_json::from_value(json).unwrap();
    assert_eq!(decoded.digest().unwrap(), free.digest().unwrap());
    assert_ne!(bounded.digest().unwrap(), free.digest().unwrap());
    for alg in [Algorithm::Keygen, Algorithm::Dec] {
        let mut bad = bounded.clone();
        bad.algorithm = alg;
        assert!(bad.validate().is_err());
    }
    let mut bad = bounded.clone();
    bad.variant = Variant::Sha;
    assert!(bad.validate().is_err());
    bad = bounded.clone();
    bad.layout = Layout::SpecializedRadix4Periodic;
    assert!(bad.validate().is_err());
    bad = bounded.clone();
    bad.params.kappa = 8;
    assert!(bad.validate().is_err());
}
#[test]
/// Checks all digit patterns without changing public schedules or AIR geometry.
fn digit8_geometry_public_schedule_and_all_digit_patterns() {
    for n in [16, 64, 4096] {
        let (s, w) = fixture(n);
        let mut free = s.clone();
        free.message_policy = EncMessagePolicy::Unrestricted;
        let old = compile_trace(&free, Some(&w)).unwrap();
        let new = compile_trace(&s, Some(&w)).unwrap();
        let public = compile_trace(&s, None).unwrap();
        assert_eq!(old.air.main_width(), new.air.main_width());
        assert_eq!(new.air.main_width(), 14);
        assert_eq!(new.air.pre_width(), 34);
        assert_eq!(new.air.rows, old.air.rows);
        assert_eq!(
            old.air
                .specialized
                .as_ref()
                .unwrap()
                .preprocessed_trace()
                .unwrap()
                .values,
            new.air
                .specialized
                .as_ref()
                .unwrap()
                .preprocessed_trace()
                .unwrap()
                .values
        );
        assert_eq!(
            new.air
                .specialized
                .as_ref()
                .unwrap()
                .preprocessed_trace()
                .unwrap()
                .values,
            public
                .air
                .specialized
                .as_ref()
                .unwrap()
                .preprocessed_trace()
                .unwrap()
                .values
        );
        assert_eq!(old.private_ntts, new.private_ntts);
        if n == 4096 {
            assert_eq!(new.air.rows, 32768);
            for b in [8, 16] {
                let report = preflight_security(&new.air, profile(b)).unwrap();
                let base = preflight_security(&old.air, profile(b)).unwrap();
                for k in [
                    "main_width",
                    "preprocessed_width",
                    "original_rows",
                    "constraint_degree",
                    "quotient_chunks",
                    "permutation_extension_columns",
                    "lookup_interactions_per_row",
                    "main_next_columns",
                ] {
                    assert_eq!(report[k], base[k], "{k}");
                }
                assert_eq!(report["quotient_chunks"], 8);
                assert_eq!(report["constraint_degree"], 4);
            }
        }
    }
    for pattern in 0..11 {
        let (mut s, mut w) = fixture(16);
        w.message = (0..16)
            .map(|j| {
                F::from_u8(if pattern < 8 {
                    pattern
                } else if pattern == 8 {
                    if j % 2 == 0 { 0 } else { 7 }
                } else if pattern == 9 {
                    j % 8
                } else {
                    0
                })
            })
            .collect();
        ciphertext(&mut s, &w);
        let c = compile_trace(&s, Some(&w)).unwrap();
        c.air.specialized.as_ref().unwrap().check(&c.trace).unwrap();
    }
}
#[test]
/// Rejects malformed bits, range witnesses, wire copies, and ciphertexts.
fn digit8_rejects_bad_auxiliary_range_copy_and_ciphertext() {
    let (mut s, mut w) = fixture(16);
    w.message.fill(F::ZERO);
    ciphertext(&mut s, &w);
    let c = compile_trace(&s, Some(&w)).unwrap();
    let row = message_row(&c);
    let width = c.air.main_width();
    let air = c.air.specialized.as_ref().unwrap();
    for (col, value) in [(12, F::TWO), (13, F::TWO), (12, F::ONE), (13, F::ONE)] {
        let mut bad = c.trace.clone();
        bad.values[row * width + col] = value;
        assert!(air.check(&bad).is_err());
    }

    let mut decoy = c.trace.clone();
    decoy.values[row * width] = F::from_u8(7);
    air.check(&decoy).unwrap();

    let mut bad = c.trace.clone();
    bad.values[row * width + 1] += F::ONE;
    bad.values[row * width + 2] += F::ONE;
    assert!(air.check(&bad).is_err());
    let mut changed = s.clone();
    changed.c0[0] = (F::from_u64(s.c0[0]) + F::ONE).as_canonical_u64();

    assert!(compile_trace(&changed, Some(&w)).is_err());
    for value in [8, 9, Q - 1, Q - 7, Q / 2] {
        let mut badw = w.clone();
        badw.message[0] = F::from_u64(value);
        let mut bads = s.clone();
        ciphertext(&mut bads, &badw);
        assert!(compile_trace(&bads, Some(&badw)).is_err());

        let mut free = bads.clone();
        free.message_policy = EncMessagePolicy::Unrestricted;
        let badtrace = compile_trace(&free, Some(&badw)).unwrap();
        badtrace
            .air
            .specialized
            .as_ref()
            .unwrap()
            .check(&badtrace.trace)
            .unwrap();
        let bounded = compile_trace(&bads, None).unwrap();
        assert!(
            bounded
                .air
                .specialized
                .as_ref()
                .unwrap()
                .check(&badtrace.trace)
                .is_err()
        );
    }
}
#[test]
/// Checks real hiding proofs and rejection of a downgraded message policy.
fn digit8_real_hiding_proofs_and_no_policy_downgrade() {
    let (s, w) = fixture(4096);
    let compiled = compile_trace(&s, Some(&w)).unwrap();
    for b in [8, 16] {
        let prover =
            Prepared::with_profile(compiled.air.clone(), s.digest().unwrap(), profile(b)).unwrap();
        let wire = prover
            .encode(prover.prove(&compiled.trace).unwrap(), true)
            .unwrap()
            .bytes;
        drop(prover);
        let public = compile_trace(&s, None).unwrap();
        let verifier = Prepared::with_profile(public.air, s.digest().unwrap(), profile(b)).unwrap();
        verifier.verify(&verifier.decode(&wire).unwrap()).unwrap();
        assert!(verifier.security["proven_rbr_bits"].as_f64().unwrap() >= 128.);
        assert!(verifier.security["ldr_non_hash_bits"].as_f64().unwrap() >= 144.);
        let mut free = s.clone();
        free.message_policy = EncMessagePolicy::Unrestricted;
        let p = Prepared::with_profile(
            compile_trace(&free, None).unwrap().air,
            free.digest().unwrap(),
            profile(b),
        )
        .unwrap();
        assert!(p.decode(&wire).is_err());
        eprintln!(
            "digit8 N4096 B{b}: {} bytes; {}",
            wire.len(),
            verifier.security
        );
    }
    let (mut s, mut w) = fixture(16);
    w.message.fill(F::ZERO);
    w.message[0] = F::from_u8(8);
    ciphertext(&mut s, &w);
    let mut free = s.clone();
    free.message_policy = EncMessagePolicy::Unrestricted;
    let invalid = compile_trace(&free, Some(&w)).unwrap();
    let p = Prepared::with_profile(
        compile_trace(&s, None).unwrap().air,
        s.digest().unwrap(),
        profile(8),
    )
    .unwrap();
    if let Ok(mut proof) = p.prove(&invalid.trace) {
        assert!(p.verify(&proof).is_err());
        proof.lookup_terminals[0].as_mut().unwrap().0 = crate::backend::E::ZERO;
        assert!(p.verify(&proof).is_err());
    }
    let freep = Prepared::with_profile(invalid.air, free.digest().unwrap(), profile(8)).unwrap();
    let wire = freep
        .encode(freep.prove(&invalid.trace).unwrap(), true)
        .unwrap()
        .bytes;
    assert!(p.decode(&wire).is_err());
}
