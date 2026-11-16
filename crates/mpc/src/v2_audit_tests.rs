use super::*;
use crate::{
    arithmetic::{BF, Q, encode, naive_mul, signed},
    backend::{E, Prepared, ProverOptions},
    fri_profile::FriProfile,
    protocol::{Fixtures, Layout, Params},
};
use rand::{SeedableRng, rngs::StdRng};
/// Constructs the selected B8 or B16 FRI profile.
fn profile(b: usize) -> FriProfile {
    FriProfile {
        log_blowup: b.ilog2() as usize,
        num_queries: if b == 8 { 100 } else { 75 },
        max_log_arity: 3,
        log_final_poly_len: 6,
    }
}
/// Constructs the public statements and witnesses for the selected variant.
fn statements(n: usize) -> Vec<(Statement, Witness)> {
    Fixtures::generate_digit8(
        Params::provisional(n).unwrap(),
        &mut StdRng::seed_from_u64(2026111401),
    )
    .unwrap()
    .statements(Variant::Pk, Layout::SpecializedRadix4Fused)
    .into_iter()
    .map(|(mut s, w)| {
        if s.algorithm == Algorithm::Enc {
            s.message_policy = EncMessagePolicy::Unsigned8Quadratic;
        }
        (s, w)
    })
    .collect()
}

/// Recomputes public ring equations for an adversarial witness.
fn rebind(s: &mut Statement, w: &Witness) {
    let n = s.params.n;
    let a = parse_poly(&s.a, n).unwrap();
    let au = naive_mul(&a, &w.secret);
    match s.algorithm {
        Algorithm::Keygen => {
            s.b = encode(
                &au.iter()
                    .zip(&w.error)
                    .map(|(&x, &e)| e - x)
                    .collect::<Vec<_>>(),
            )
        }
        Algorithm::Enc => {
            let bu = naive_mul(&parse_poly(&s.b, n).unwrap(), &w.secret);
            s.c0 = encode(
                &(0..n)
                    .map(|j| bu[j] + w.e0[j] + F::from_u64(s.params.kappa) * w.message[j])
                    .collect::<Vec<_>>(),
            );
            s.c1 = encode(&(0..n).map(|j| au[j] + w.e1[j]).collect::<Vec<_>>());
        }
        Algorithm::Dec => {
            s.b = encode(&(0..n).map(|j| w.error[j] - au[j]).collect::<Vec<_>>());
            let cs = naive_mul(&parse_poly(&s.c1, n).unwrap(), &w.secret);
            s.d = encode(&(0..n).map(|j| cs[j] + w.flood[j]).collect::<Vec<_>>());
        }
    }
}
/// Constructs the arithmetic AIR and trace without local witness rejection.
fn raw(s: &Statement, w: &Witness) -> (SpecializedAir, RowMajorMatrix<F>) {
    build(s, Some(w)).unwrap().0.finish()
}
/// Checks that an invalid trace fails native proof verification.
fn reject_real(s: &Statement, trace: &RowMajorMatrix<F>) {
    let c = compile_trace(s, None).unwrap();
    assert!(c.air.specialized.as_ref().unwrap().check(trace).is_err());
    for b in [8, 16] {
        let p = Prepared::with_profile(c.air.clone(), s.digest().unwrap(), profile(b)).unwrap();
        if let Ok(mut proof) = p.prove(trace) {
            assert!(p.verify(&proof).is_err());
            proof.lookup_terminals[0].as_mut().unwrap().0 = E::ZERO;
            assert!(p.verify(&proof).is_err());
        }
    }
}
/// Checks the local equations independently of the lookup multiset.
fn local_constraints_hold(air: &SpecializedAir, trace: &RowMajorMatrix<F>) -> bool {
    let mut balance = HashMap::new();
    for r in 0..air.rows {
        let width = air.main_width();
        let cur = &trace.values[r * width..(r + 1) * width];
        let next = (r + 1) % air.rows;
        let nxt = &trace.values[next * width..(next + 1) * width];
        let prep = air.preprocessed_row(r);
        let mut checker = Checker {
            main: RowWindow::from_two_rows(cur, nxt),
            prep: RowWindow::from_two_rows(prep, prep),
            failures: 0,
            balance: &mut balance,
            periodic: &[],
        };
        air.eval(&mut checker);
        if checker.failures != 0 {
            return false;
        }
    }
    true
}
#[test]
/// Rejects invalid bounds and Hamming weights even with matching public equations.
fn audit_v2_recomputed_bad_witnesses_do_not_bypass_bounds_or_hw() {
    for (s, w) in statements(16).into_iter().filter(|(s, _)| s.party == 0) {
        for j in [0, 1, 14, 15] {
            let mut bad = w.clone();
            bad.secret[j] = F::TWO;
            let mut target = s.clone();
            rebind(&mut target, &bad);
            let (air, t) = raw(&target, &bad);
            assert!(air.check(&t).is_err());
            if s.algorithm != Algorithm::Enc {
                bad = w.clone();
                bad.secret.fill(F::ZERO);
                bad.secret[14] = F::ONE;
                bad.secret[15] = F::ONE;
                target = s.clone();
                rebind(&mut target, &bad);
                let (air, t) = raw(&target, &bad);
                assert!(air.check(&t).is_err());
            }
            for negative in [false, true] {
                bad = w.clone();
                let value = signed(if negative { -27 } else { 27 });
                if s.algorithm == Algorithm::Enc {
                    bad.e0[j] = value;
                } else {
                    bad.error[j] = value;
                }
                target = s.clone();
                rebind(&mut target, &bad);
                let (air, t) = raw(&target, &bad);
                assert!(air.check(&t).is_err());
                if s.algorithm == Algorithm::Enc {
                    bad = w.clone();
                    bad.e1[j] = value;
                    target = s.clone();
                    rebind(&mut target, &bad);
                    let (air, t) = raw(&target, &bad);
                    assert!(air.check(&t).is_err());
                }
            }
        }
        let mut bad = w.clone();
        match s.algorithm {
            Algorithm::Keygen => {
                bad.secret.fill(F::ZERO);
                bad.secret[14] = F::ONE;
                bad.secret[15] = F::ONE;
            }
            Algorithm::Enc => bad.e1[15] = signed(27),
            Algorithm::Dec => bad.flood[15] = signed(BF + 1),
        }
        let mut target = s.clone();
        rebind(&mut target, &bad);
        let (_, t) = raw(&target, &bad);
        reject_real(&target, &t);
        if s.algorithm == Algorithm::Dec {
            for value in [BF, -BF] {
                bad = w.clone();
                bad.flood[15] = signed(value);
                target = s.clone();
                rebind(&mut target, &bad);
                let (air, t) = raw(&target, &bad);
                air.check(&t).unwrap();
            }
            for value in [BF + 1, -BF - 1, (1i64 << 59) - 1] {
                bad = w.clone();
                bad.flood[15] = signed(value);
                target = s.clone();
                rebind(&mut target, &bad);
                let (air, t) = raw(&target, &bad);
                assert!(air.check(&t).is_err());
            }
        }
    }
}
#[test]
/// Rejects locally valid traces with false wire copies or byte lookups.
fn audit_v2_locally_valid_copy_and_byte_attacks_fail_native_verification() {
    for (mut s, mut w) in statements(16).into_iter().filter(|(s, _)| s.party == 0) {
        if s.algorithm == Algorithm::Keygen {
            let (air, mut t) = raw(&s, &w);
            let r = (0..air.rows)
                .find(|&r| air.preprocessed_row(r)[BUTTERFLY + 8] == F::ONE)
                .unwrap();
            let delta = air.preprocessed_row(r)[COEFF + 8];
            let width = air.main_width();
            t.values[r * width] += F::ONE;
            for i in 4..8 {
                t.values[r * width + i] += delta;
            }
            assert!(local_constraints_hold(&air, &t));
            assert!(air.check(&t).unwrap_err().contains("multiset"));
            reject_real(&s, &t);
        }
        if s.algorithm == Algorithm::Dec {
            w.flood.fill(F::ZERO);
            w.flood[0] = F::from_u16(256);
            rebind(&mut s, &w);
            let (air, mut t) = raw(&s, &w);
            let r = (0..air.rows)
                .find(|&r| air.preprocessed_row(r)[FLOOD + 8] == F::ONE)
                .unwrap();
            let width = air.main_width();
            assert_eq!(t.values[r * width + 2], F::ZERO);
            assert_eq!(t.values[r * width + 3], F::ONE);

            t.values[r * width + 2] = F::from_u16(256);
            t.values[r * width + 3] = F::ZERO;
            assert!(local_constraints_hold(&air, &t));
            assert!(air.check(&t).unwrap_err().contains("multiset"));
            reject_real(&s, &t);
        }
    }
}
#[test]
/// Checks binding of all non-arithmetic public context fields.
fn audit_v2_public_context_binds_fields_not_used_in_the_arithmetic() {
    assert_eq!(Q, 18446744069414584321);
    assert_eq!(BF, 366857376337484500);
    let params = Params::provisional(4096).unwrap();
    assert_eq!(params.h, 256);
    assert_eq!(params.kappa, 2305843008676823040);
    let psi = arithmetic::root(4096);
    assert_eq!(psi.exp_u64(8192), F::ONE);
    assert_eq!(psi.exp_u64(4096), -F::ONE);
    assert!(parse_poly(&[Q], 1).is_err());
    assert!(parse_poly(&[u64::MAX], 1).is_err());
    for (s, _) in statements(16) {
        let d = s.digest().unwrap();
        for field in 0..5 {
            let mut other = s.clone();
            match field {
                0 => other.key_id[0] ^= 1,
                1 => other.roster[0] ^= 1,
                2 => other.session[0] ^= 1,
                3 => other.party ^= 1,
                _ => {
                    if other.algorithm == Algorithm::Dec {
                        other.c0[0] = (other.c0[0] + 1) % Q;
                    } else {
                        continue;
                    }
                }
            };
            assert_ne!(d, other.digest().unwrap());
        }
    }
}
#[test]
/// Verifies both parties and both profiles through cached and original verifiers.
fn audit_v2_n4096_both_parties_both_profiles_cached_and_original_verifier() {
    for (s, w) in statements(4096) {
        let c = compile_trace(&s, Some(&w)).unwrap();
        assert_eq!(
            c.private_ntts,
            if s.algorithm == Algorithm::Keygen {
                2
            } else {
                3
            }
        );
        for b in [8, 16] {
            let p = Prepared::with_profile(c.air.clone(), s.digest().unwrap(), profile(b)).unwrap();
            let sec = p.security.clone();
            assert_eq!(sec["original_rows"], 32768);
            assert_eq!(sec["preprocessed_width"], 34);
            assert_eq!(sec["constraint_degree"], 4);
            assert_eq!(sec["quotient_chunks"], 8);
            assert_eq!(
                sec["constraints"],
                match s.algorithm {
                    Algorithm::Keygen => 31,
                    Algorithm::Enc => 29,
                    Algorithm::Dec => 43,
                }
            );
            assert_eq!(
                sec["main_width"],
                if s.algorithm == Algorithm::Dec {
                    15
                } else {
                    14
                }
            );
            assert!(sec["proven_rbr_bits"].as_f64().unwrap() >= 128.);
            assert!(sec["ldr_non_hash_bits"].as_f64().unwrap() >= 144.);
            let wire = p.encode(p.prove(&c.trace).unwrap(), true).unwrap().bytes;
            drop(p);
            for cached in [true, false] {
                let public = compile_trace(&s, None).unwrap();
                let v = Prepared::with_verifier_cache(
                    public.air,
                    s.digest().unwrap(),
                    profile(b),
                    ProverOptions::default(),
                    cached,
                )
                .unwrap();
                assert_eq!(sec, v.security);
                v.verify(&v.decode(&wire).unwrap()).unwrap();
            }
            eprintln!("AUDIT N4096 {:?} party{} B{b}: {sec}", s.algorithm, s.party);
        }
    }
}
