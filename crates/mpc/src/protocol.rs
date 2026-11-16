use crate::{arithmetic::*, sampler};
use p3_field::PrimeCharacteristicRing;
use rand::{CryptoRng, RngExt};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Variant {
    Sha,
    Pk,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    Keygen,
    Enc,
    Dec,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Layout {
    SpecializedRadix4Fused = 11,
    SpecializedRadix4Periodic = 12,
}
impl Layout {
    /// Selects the retained AIR layout for the requested key-binding variant.
    pub fn for_variant(variant: Variant) -> Self {
        match variant {
            Variant::Sha => Self::SpecializedRadix4Periodic,
            Variant::Pk => Self::SpecializedRadix4Fused,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShaImplementation {
    NotUsed,
    OfficialPeriodic,
}
impl ShaImplementation {
    pub const DEFAULT: Self = Self::OfficialPeriodic;
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Params {
    pub n: usize,
    pub h: usize,
    pub kappa: u64,
    pub lift: String,
}
impl Params {
    /// Constructs the explicit provisional digit-lift parameter profile.
    pub fn provisional(n: usize) -> Result<Self, String> {
        if !n.is_power_of_two() || !(16..=4096).contains(&n) {
            return Err("N must be a power of two in 16..=4096".into());
        }
        Ok(Self {
            n,
            h: if n == 4096 { 256 } else { n / 16 },
            kappa: (Q - 1) / 8,
            lift: "provisional-digit-lift-(q-1)/8".into(),
        })
    }
    /// Rejects unsupported or inconsistent parameter selections.
    pub fn validate(&self) -> Result<(), String> {
        if *self != Self::provisional(self.n)? {
            return Err("unsupported or ambiguous parameter profile".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncMessagePolicy {
    #[default]
    Unrestricted,
    Unsigned8Quadratic,
}
impl EncMessagePolicy {
    /// Reports whether the statement omits the message-range requirement.
    pub fn is_unrestricted(&self) -> bool {
        *self == Self::Unrestricted
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    pub params: Params,
    pub variant: Variant,
    pub algorithm: Algorithm,
    pub layout: Layout,
    pub sha_implementation: ShaImplementation,
    #[serde(default, skip_serializing_if = "EncMessagePolicy::is_unrestricted")]
    pub message_policy: EncMessagePolicy,
    pub key_id: [u8; 32],
    pub roster: [u8; 32],
    pub party: u8,
    pub session: [u8; 32],
    pub authorized_request: [u8; 32],
    pub a: Vec<u64>,
    pub b: Vec<u64>,
    pub c0: Vec<u64>,
    pub c1: Vec<u64>,
    pub d: Vec<u64>,
    pub key_hash: Option<[u8; 32]>,
}
impl Statement {
    /// Rejects unsupported or inconsistent parameter selections.
    pub fn validate(&self) -> Result<(), String> {
        self.params.validate()?;
        if self.message_policy != EncMessagePolicy::Unrestricted
            && (self.algorithm != Algorithm::Enc
                || self.variant != Variant::Pk
                || self.layout != Layout::SpecializedRadix4Fused)
        {
            return Err("digit8 quadratic policy requires V2 fused ENC".into());
        }
        if self.party > 1 {
            return Err("party must be 0 or 1".into());
        }
        let n = self.params.n;
        let expected = match self.algorithm {
            Algorithm::Keygen => [n, n, 0, 0, 0],
            Algorithm::Enc => [n, n, n, n, 0],
            Algorithm::Dec => {
                if self.variant == Variant::Pk {
                    [n, n, n, n, n]
                } else {
                    [0, 0, n, n, n]
                }
            }
        };
        for (poly, &len) in [&self.a, &self.b, &self.c0, &self.c1, &self.d]
            .iter()
            .zip(&expected)
        {
            parse_poly(poly, len)?;
        }
        if self.key_hash.is_some()
            != (self.variant == Variant::Sha && self.algorithm != Algorithm::Enc)
        {
            return Err("unexpected/missing key commitment".into());
        }
        if self.key_hash.is_some() == (self.sha_implementation == ShaImplementation::NotUsed) {
            return Err("SHA implementation must match the key-binding relation".into());
        }
        if self.layout != Layout::for_variant(self.variant) {
            return Err("layout does not match the selected variant".into());
        }
        if self.algorithm != Algorithm::Dec && self.authorized_request != [0; 32] {
            return Err("unexpected authorization digest".into());
        }
        Ok(())
    }

    /// Serializes the statement into its unique authenticated byte encoding.
    pub fn canonical(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut v = vec![];
        let text = |v: &mut Vec<u8>, s: &[u8]| {
            v.extend((s.len() as u32).to_le_bytes());
            v.extend(s);
        };
        text(&mut v, b"VMPCKKS/v3/circuit-statement/2");
        v.extend([
            self.variant as u8,
            self.algorithm as u8,
            self.layout as u8,
            self.party,
        ]);
        match self.sha_implementation {
            ShaImplementation::NotUsed => v.push(0),
            ShaImplementation::OfficialPeriodic => {
                v.push(4);
                v.extend(crate::periodic_sha::PeriodicSha::digest());
            }
        }
        v.extend((self.params.n as u32).to_le_bytes());
        v.extend((self.params.h as u32).to_le_bytes());
        v.extend(Q.to_le_bytes());
        v.extend(BF.to_le_bytes());
        v.extend(self.params.kappa.to_le_bytes());
        text(&mut v, self.params.lift.as_bytes());
        for x in [
            &self.key_id,
            &self.roster,
            &self.session,
            &self.authorized_request,
        ] {
            v.extend(x);
        }
        for p in [&self.a, &self.b, &self.c0, &self.c1, &self.d] {
            v.extend((p.len() as u32).to_le_bytes());
            for &x in p {
                v.extend(x.to_le_bytes());
            }
        }
        match self.key_hash {
            Some(x) => {
                v.push(1);
                v.extend(x);
            }
            None => v.push(0),
        }
        if self.message_policy == EncMessagePolicy::Unsigned8Quadratic {
            text(
                &mut v,
                b"VMPCKKS/enc-message/unsigned8-quadratic/1:all-coefficients",
            );
        }
        Ok(v)
    }
    /// Returns the authenticated encoding digest.
    pub fn digest(&self) -> Result<[u8; 32], String> {
        Ok(hash(&self.canonical()?))
    }
}
#[derive(Clone)]
pub struct Witness {
    pub secret: Vec<F>,
    pub error: Vec<F>,
    pub e0: Vec<F>,
    pub e1: Vec<F>,
    pub message: Vec<F>,
    pub flood: Vec<F>,
    pub salt: [u8; 32],
}
impl Witness {
    /// Creates zero placeholders for public-only circuit construction.
    pub fn empty(n: usize) -> Self {
        Self {
            secret: vec![F::ZERO; n],
            error: vec![F::ZERO; n],
            e0: vec![F::ZERO; n],
            e1: vec![F::ZERO; n],
            message: vec![F::ZERO; n],
            flood: vec![F::ZERO; n],
            salt: [0; 32],
        }
    }
}
pub struct CompiledTrace {
    pub air: crate::circuit::CircuitAir,
    pub trace: p3_matrix::dense::RowMajorMatrix<F>,
    pub private_ntts: usize,
    pub sha_blocks: usize,
    pub operations: usize,
}
/// Constructs the current composite AIR and its witness or placeholder trace.
pub fn compile_trace(stmt: &Statement, witness: Option<&Witness>) -> Result<CompiledTrace, String> {
    stmt.validate()?;
    crate::specialized::compile_trace(stmt, witness)
}

pub struct Fixtures {
    pub params: Params,
    pub key_id: [u8; 32],
    pub sessions: [[u8; 32]; 3],
    pub a: Vec<F>,
    pub b: Vec<F>,
    pub shares: [Vec<F>; 2],
    pub keys: [Witness; 2],
    pub enc: [Witness; 2],
    pub ciphertexts: [(Vec<F>, Vec<F>); 2],
    pub output: (Vec<F>, Vec<F>),
    pub dec: [Witness; 2],
    pub d: [Vec<F>; 2],
    pub decoded: Vec<u8>,
    pub expected: Vec<u8>,
}
impl Fixtures {
    /// Samples a complete two-party reference workflow.
    pub fn generate(params: Params, rng: &mut impl CryptoRng) -> Result<Self, String> {
        Self::generate_with_digit_bound(params, rng, 4)
    }

    /// Samples a two-party workflow using the complete unsigned digit domain.
    pub fn generate_digit8(params: Params, rng: &mut impl CryptoRng) -> Result<Self, String> {
        Self::generate_with_digit_bound(params, rng, 8)
    }
    /// Samples a reference workflow with the specified message bound.
    fn generate_with_digit_bound(
        params: Params,
        rng: &mut impl CryptoRng,
        bound: u8,
    ) -> Result<Self, String> {
        params.validate()?;
        let n = params.n;

        let a: Vec<F> = (0..n).map(|_| rng.random()).collect();
        let key_id = rng.random();
        let sessions = rng.random();
        let keys = core::array::from_fn(|_| {
            let mut w = Witness::empty(n);
            w.secret = sampler::sparse(n, params.h, rng);
            w.error = sampler::small(n, rng);
            w.salt = rng.random();
            w
        });
        let shares = core::array::from_fn(|i| keygen(&a, &keys[i].secret, &keys[i].error));
        let b = add(&shares[0], &shares[1]);
        let enc = core::array::from_fn(|_| {
            let mut w = Witness::empty(n);
            w.secret = sampler::ternary(n, rng);
            w.e0 = sampler::small(n, rng);
            w.e1 = sampler::small(n, rng);
            w.message = (0..n)
                .map(|_| F::from_u8(rng.random_range(0..bound)))
                .collect();
            w
        });
        let ciphertexts = core::array::from_fn(|i| enc_fn(&a, &b, &enc[i], params.kappa));

        let output = (
            add(&ciphertexts[0].0, &ciphertexts[1].0),
            add(&ciphertexts[0].1, &ciphertexts[1].1),
        );
        let dec = core::array::from_fn(|i| {
            let mut w = keys[i].clone();
            w.flood = sampler::flooding(n, rng);
            w
        });
        let d = core::array::from_fn(|i| {
            crate::arithmetic::dec(&output.1, &dec[i].secret, &dec[i].flood)
        });
        let decoded = add(&add(&output.0, &d[0]), &d[1])
            .into_iter()
            .map(decode_digit)
            .collect::<Vec<_>>();
        let expected = add(&enc[0].message, &enc[1].message)
            .into_iter()
            .map(|x| center(x) as u8 % 8)
            .collect::<Vec<_>>();
        if decoded != expected {
            return Err("reference decryption failed".into());
        }
        Ok(Self {
            params,
            key_id,
            sessions,
            a,
            b,
            shares,
            keys,
            enc,
            ciphertexts,
            output,
            dec,
            d,
            decoded,
            expected,
        })
    }
    /// Constructs the public statements and witnesses for the selected variant.
    pub fn statements(&self, variant: Variant, layout: Layout) -> Vec<(Statement, Witness)> {
        let hashes: [Option<[u8; 32]>; 2] = core::array::from_fn(|i| {
            if variant == Variant::Sha {
                Some(hash(&key_message(&self.keys[i].secret, &self.keys[i].salt)))
            } else {
                None
            }
        });
        let mut roster_bytes = b"VMPCKKS/v3/roster".to_vec();
        roster_bytes.extend(self.key_id);
        for i in 0..2 {
            roster_bytes.push(i as u8);
            for x in encode(&self.shares[i]) {
                roster_bytes.extend(x.to_le_bytes());
            }
            if let Some(t) = hashes[i] {
                roster_bytes.extend(t);
            }
        }
        let roster = hash(&roster_bytes);
        let mut out = vec![];
        for algorithm in [Algorithm::Keygen, Algorithm::Enc, Algorithm::Dec] {
            for (i, key_hash) in hashes.iter().enumerate() {
                let mut s = Statement {
                    params: self.params.clone(),
                    message_policy: EncMessagePolicy::Unrestricted,
                    variant,
                    algorithm,
                    layout,
                    sha_implementation: if key_hash.is_some() && algorithm != Algorithm::Enc {
                        ShaImplementation::DEFAULT
                    } else {
                        ShaImplementation::NotUsed
                    },
                    key_id: self.key_id,
                    roster,
                    party: i as u8,
                    session: self.sessions[algorithm as usize],
                    authorized_request: [0; 32],
                    a: vec![],
                    b: vec![],
                    c0: vec![],
                    c1: vec![],
                    d: vec![],
                    key_hash: if algorithm == Algorithm::Enc {
                        None
                    } else {
                        *key_hash
                    },
                };
                let witness = match algorithm {
                    Algorithm::Keygen => {
                        s.a = encode(&self.a);
                        s.b = encode(&self.shares[i]);
                        self.keys[i].clone()
                    }
                    Algorithm::Enc => {
                        s.a = encode(&self.a);
                        s.b = encode(&self.b);
                        s.c0 = encode(&self.ciphertexts[i].0);
                        s.c1 = encode(&self.ciphertexts[i].1);
                        self.enc[i].clone()
                    }
                    Algorithm::Dec => {
                        if variant == Variant::Pk {
                            s.a = encode(&self.a);
                            s.b = encode(&self.shares[i]);
                        }
                        s.c0 = encode(&self.output.0);
                        s.c1 = encode(&self.output.1);
                        s.d = encode(&self.d[i]);
                        let mut request = b"VMPCKKS/v3/authorized-output".to_vec();
                        request.extend(s.key_id);
                        request.extend(s.session);
                        for poly in [&s.c0, &s.c1] {
                            for x in poly {
                                request.extend(x.to_le_bytes());
                            }
                        }
                        s.authorized_request = hash(&request);
                        self.dec[i].clone()
                    }
                };
                out.push((s, witness));
            }
        }
        out
    }
}
/// Encrypts a fixture witness using the shared reference arithmetic.
fn enc_fn(a: &[F], b: &[F], w: &Witness, k: u64) -> (Vec<F>, Vec<F>) {
    crate::arithmetic::enc(a, b, &w.secret, &w.e0, &w.e1, &w.message, F::from_u64(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    #[test]
    /// Checks current relation schedules and rejects inconsistent private witnesses.
    fn active_relations_preserve_public_schedules_and_reject_bad_witnesses() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(123);
        let f = Fixtures::generate_digit8(Params::provisional(64).unwrap(), &mut rng).unwrap();
        for variant in [Variant::Sha, Variant::Pk] {
            for (mut s, w) in f.statements(variant, Layout::for_variant(variant)) {
                if variant == Variant::Pk && s.algorithm == Algorithm::Enc {
                    s.message_policy = EncMessagePolicy::Unsigned8Quadratic;
                }
                let c = compile_trace(&s, Some(&w)).unwrap();
                let p = compile_trace(&s, None).unwrap();
                use p3_air::BaseAir;
                assert_eq!(
                    c.air.preprocessed_trace().unwrap().values,
                    p.air.preprocessed_trace().unwrap().values
                );
                let mut bad = w.clone();
                match s.algorithm {
                    Algorithm::Keygen => bad.error[0] += F::ONE,
                    Algorithm::Enc => bad.e0[0] += F::ONE,
                    Algorithm::Dec => bad.flood[0] += F::ONE,
                }
                assert!(compile_trace(&s, Some(&bad)).is_err());
            }
        }
    }
}
