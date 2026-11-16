use crate::{
    arithmetic::{F, TAG, hash},
    generated_sha,
    narrow_sha::Compiler,
};
use p3_air::AirBuilder;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
#[cfg(test)]
use p3_sha256_air::Sha256Cols;
use p3_sha256_air::{INPUT_WORDS, NUM_SHA256_COLS, SHA256_IV, generate_trace_rows};
#[cfg(test)]
use std::borrow::Borrow;
#[cfg(test)]
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

const SLOTS: usize = 72;
const WIDTH: usize = SLOTS + 1;
const CONTROLS: usize = 9;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Gate {
    template: usize,
    offset: usize,
    parameter_offset: usize,
}
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
enum Wrapper {
    Iv(usize),
    Digest(usize),
    Padding(usize),
    Incoming(usize),
    Outgoing(usize),
}
#[derive(Default, Debug, serde::Serialize, serde::Deserialize)]
struct Row {
    inputs: Vec<usize>,
    equations: Vec<(usize, usize)>,
    definition: bool,
    boolean: bool,
    wrapper: Option<Wrapper>,
}
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Plan {
    #[serde(skip, default = "Compiler::shared")]
    compiler: Arc<Compiler>,
    rows: Vec<Row>,
    gates: Vec<Gate>,
    periodic: Vec<Vec<F>>,
    params: usize,
    extra: usize,
    stride: usize,
    max_multiplicity: u32,
    equation_rows: usize,
    digest: [u8; 32],
}
impl Plan {
    /// Loads and authenticates the shared frozen periodic SHA plan.
    fn shared() -> Arc<Self> {
        static PLAN: OnceLock<Arc<Plan>> = OnceLock::new();
        PLAN.get_or_init(|| {
            let bytes = include_bytes!("sha_frozen/periodic.bin");
            let p = postcard::from_bytes::<Self>(bytes).expect("embedded periodic plan");
            assert_eq!(p.binding_digest(), PeriodicSha::PLAN_DIGEST);
            Arc::new(p)
        })
        .clone()
    }
    /// Computes the binding digest for the periodic SHA plan.
    fn binding_digest(&self) -> [u8; 32] {
        let mut bytes = b"SHA256BENCH/packed-periodic-plan/1\0".to_vec();
        bytes.extend(Compiler::DIGEST);
        bytes.extend(
            postcard::to_allocvec(&(self.stride, &self.gates, self.extra - self.params)).unwrap(),
        );
        for c in &self.periodic {
            for v in c {
                bytes.extend(v.as_canonical_u64().to_le_bytes());
            }
        }
        hash(&bytes)
    }
    #[cfg(test)]
    /// Rebuilds the periodic equation packing and public control plan.
    fn compile() -> Self {
        let compiler = Compiler::shared();
        let mut order: Vec<_> = (0..compiler.equations.len()).collect();
        order.sort_by_key(|&i| (std::cmp::Reverse(compiler.equations[i].inputs.len()), i));
        let mut rows: Vec<Row> = Vec::new();
        for index in order {
            let equation = &compiler.equations[index];
            let len = equation.inputs.len();
            let best = rows
                .iter()
                .enumerate()
                .filter(|(_, r)| r.inputs.len() + len <= SLOTS)
                .min_by_key(|(i, r)| (SLOTS - r.inputs.len() - len, *i))
                .map(|(i, _)| i);
            let index_row = best.unwrap_or_else(|| {
                rows.push(Row::default());
                rows.len() - 1
            });
            let r = &mut rows[index_row];
            r.equations.push((index, r.inputs.len()));
            r.inputs.extend_from_slice(&equation.inputs);
        }
        let equation_rows = rows.len();

        assert_eq!(equation_rows, 780);
        for boolean in [true, false] {
            let columns: Vec<_> = (0..NUM_SHA256_COLS)
                .filter(|&i| compiler.booleans[i] == boolean)
                .collect();
            for chunk in columns.chunks(SLOTS) {
                rows.push(Row {
                    inputs: chunk.to_vec(),
                    definition: true,
                    boolean,
                    ..Row::default()
                });
            }
        }
        let columns: Vec<_> = (0..NUM_SHA256_COLS).collect();
        let c: &Sha256Cols<usize> = columns.as_slice().borrow();
        for i in 0..16 {
            rows.push(Row {
                inputs: vec![c.h_in[i / 2][i % 2]],
                wrapper: Some(Wrapper::Iv(i)),
                ..Row::default()
            });
        }
        for i in 0..16 {
            rows.push(Row {
                inputs: c.h_out[i / 2][16 * (i % 2)..16 * (i % 2) + 16].to_vec(),
                wrapper: Some(Wrapper::Digest(i)),
                ..Row::default()
            });
        }
        for byte in 0..64 {
            let inputs = (0..8)
                .map(|bit| c.w[byte / 4][8 * (3 - byte % 4) + bit])
                .collect();
            rows.push(Row {
                inputs,
                wrapper: Some(Wrapper::Padding(byte)),
                ..Row::default()
            });
        }
        for i in 0..16 {
            rows.push(Row {
                inputs: vec![c.h_in[i / 2][i % 2]],
                wrapper: Some(Wrapper::Incoming(i)),
                ..Row::default()
            });
        }
        for i in 0..16 {
            rows.push(Row {
                inputs: c.h_out[i / 2][16 * (i % 2)..16 * (i % 2) + 16].to_vec(),
                wrapper: Some(Wrapper::Outgoing(i)),
                ..Row::default()
            });
        }
        let mut fanout = vec![0u32; NUM_SHA256_COLS];
        for r in &rows {
            if !r.definition {
                for &i in &r.inputs {
                    fanout[i] += 1;
                }
            }
        }
        let mut gates = vec![];
        let mut ids = HashMap::new();
        let mut parameters = 0;
        for r in &rows {
            for (lane, &(index, offset)) in r.equations.iter().enumerate() {
                let e = &compiler.equations[index];
                let g = Gate {
                    template: e.template,
                    offset,
                    parameter_offset: 2 * lane,
                };
                parameters = parameters.max(2 * lane + e.parameters.len());
                ids.entry(g).or_insert_with(|| {
                    gates.push(g);
                    gates.len() - 1
                });
            }
        }
        let params = 2 * SLOTS + gates.len();
        let extra = params + parameters;
        let stride = rows.len().next_power_of_two();
        assert_eq!(stride, 1024);
        let mut periodic = vec![vec![F::ZERO; stride]; extra + 5];
        for (i, r) in rows.iter().enumerate() {
            for (slot, &column) in r.inputs.iter().enumerate() {
                periodic[slot][i] = F::from_usize(column);
                periodic[SLOTS + slot][i] = if r.definition {
                    -F::from_u32(fanout[column])
                } else {
                    F::ONE
                };
            }
            for (lane, &(index, offset)) in r.equations.iter().enumerate() {
                let e = &compiler.equations[index];
                let g = Gate {
                    template: e.template,
                    offset,
                    parameter_offset: 2 * lane,
                };
                periodic[2 * SLOTS + ids[&g]][i] = F::ONE;
                for (j, &value) in e.parameters.iter().enumerate() {
                    periodic[params + 2 * lane + j][i] = F::from_u64(value);
                }
            }
            periodic[extra][i] = F::from_bool(r.boolean);
            if let Some(wrapper) = r.wrapper {
                let flag = match wrapper {
                    Wrapper::Iv(_) | Wrapper::Incoming(_) => 1,
                    Wrapper::Padding(_) => 2,
                    _ => 3,
                };
                periodic[extra + flag][i] = F::ONE;
                periodic[extra + 4][i] = F::from_usize(match wrapper {
                    Wrapper::Incoming(limb) => limb,
                    Wrapper::Outgoing(limb) => limb + 16,
                    _ => 0,
                });
            }
        }
        let mut bytes = b"SHA256BENCH/packed-periodic-plan/1\0".to_vec();
        bytes.extend(Compiler::DIGEST);
        bytes.extend(postcard::to_allocvec(&(stride, &gates, parameters)).unwrap());
        for column in &periodic {
            for value in column {
                bytes.extend(value.as_canonical_u64().to_le_bytes());
            }
        }
        let digest = hash(&bytes);
        let max_multiplicity = fanout.into_iter().max().unwrap().max(1);
        Self {
            compiler,
            rows,
            gates,
            periodic,
            params,
            extra,
            stride,
            max_multiplicity,
            equation_rows,
            digest,
        }
    }
}

#[derive(Debug)]
pub struct PeriodicSha {
    secret_wires: Vec<usize>,
    digest: [u8; 32],
    blocks: usize,
    plan: Arc<Plan>,
    pub active_rows: usize,
    pub max_multiplicity: u32,
}
impl PeriodicSha {
    pub const PLAN_DIGEST: [u8; 32] = [
        56, 49, 236, 196, 246, 118, 59, 253, 189, 128, 184, 227, 249, 38, 122, 28, 102, 209, 69,
        13, 243, 78, 63, 61, 39, 188, 38, 187, 252, 216, 167, 242,
    ];
    /// Returns the authenticated encoding digest.
    pub fn digest() -> [u8; 32] {
        let mut binding=b"VMPCKKS/official-sha-periodic/1\0:tag-salt-pack2;controls=9;secret-bus=0;chain-bus=3;definition-bus=4".to_vec();
        binding.extend(Self::PLAN_DIGEST);
        binding.extend(Compiler::DIGEST);
        binding.extend(TAG);
        hash(&binding)
    }
    /// Constructs the periodic SHA schedule for a tagged secret commitment.
    pub fn new(secret_wires: Vec<usize>, digest: [u8; 32]) -> Self {
        let blocks = (TAG.len() + 32 + secret_wires.len() / 4 + 9).div_ceil(64);
        let plan = Plan::shared();
        Self {
            active_rows: blocks * plan.rows.len(),
            max_multiplicity: plan.max_multiplicity,
            secret_wires,
            digest,
            blocks,
            plan,
        }
    }
    #[cfg(test)]
    /// Rebuilds and serializes the frozen artifact for equivalence checks.
    pub fn frozen_bytes() -> Vec<u8> {
        postcard::to_allocvec(&Plan::compile()).unwrap()
    }
    /// Returns the main trace width.
    pub fn width(&self) -> usize {
        WIDTH
    }
    /// Returns the padded trace height required by this SHA message.
    pub fn height(&self) -> usize {
        self.blocks.next_power_of_two() * self.plan.stride
    }
    /// Returns the number of ordinary public preprocessing columns.
    pub fn pre_width(&self) -> usize {
        CONTROLS
    }
    /// Returns the number of SHA lookup interactions per row.
    pub fn interactions(&self) -> usize {
        WIDTH + 4
    }
    /// Returns the repeated public SHA column values.
    pub fn periodic(&self) -> &[Vec<F>] {
        &self.plan.periodic
    }
    /// Returns the compiler and trace geometry statistics.
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({"compiler":self.plan.compiler.report(),"layout":"fhe-packed-periodic-v1","slots":SLOTS,"width":WIDTH,"pre_width":CONTROLS,"periodic_columns":self.periodic().len(),"period":self.plan.stride,"active_rows":self.active_rows,"rows_per_compression":self.plan.rows.len(),"max_multiplicity":self.max_multiplicity,"templates":self.plan.gates.len(),"interactions_per_row":self.interactions(),"layout_digest":Self::digest()})
    }
    /// Constructs the public SHA control matrix.
    pub fn preprocessed(&self, height: usize) -> RowMajorMatrix<F> {
        assert_eq!(height, self.height());
        let mut values = vec![F::ZERO; height * CONTROLS];
        let message_len = TAG.len() + 32 + self.secret_wires.len() / 4;
        let bits = ((message_len as u64) * 8).to_be_bytes();
        for (i, p) in values.chunks_exact_mut(CONTROLS).enumerate() {
            let block = i / self.plan.stride;
            let local = i % self.plan.stride;
            p[3] = F::from_usize(block);
            if block >= self.blocks {
                continue;
            }
            let Some(row) = self.plan.rows.get(local) else {
                continue;
            };
            match row.wrapper {
                Some(Wrapper::Iv(limb)) if block == 0 => {
                    p[0] = F::ONE;
                    p[1] = F::from_u16((SHA256_IV[limb / 2] >> (16 * (limb % 2))) as u16);
                }
                Some(Wrapper::Digest(limb)) if block + 1 == self.blocks => {
                    let word = u32::from_be_bytes(
                        self.digest[4 * (limb / 2)..4 * (limb / 2) + 4]
                            .try_into()
                            .unwrap(),
                    );
                    p[0] = F::ONE;
                    p[1] = F::from_u16((word >> (16 * (limb % 2))) as u16);
                }
                Some(Wrapper::Padding(byte)) => {
                    let pos = 64 * block + byte;
                    let fixed = if pos < TAG.len() {
                        Some(TAG[pos])
                    } else if pos < message_len {
                        None
                    } else if pos == message_len {
                        Some(0x80)
                    } else if pos >= 64 * self.blocks - 8 {
                        Some(bits[pos - (64 * self.blocks - 8)])
                    } else {
                        Some(0)
                    };
                    if let Some(value) = fixed {
                        p[0] = F::ONE;
                        p[1] = F::from_u8(value);
                    }
                    if (TAG.len() + 32..message_len).contains(&pos) {
                        p[4] = F::ONE;
                        let start = 4 * (pos - TAG.len() - 32);
                        for k in 0..4 {
                            p[5 + k] = F::from_usize(self.secret_wires[start + k]);
                        }
                    }
                }
                Some(Wrapper::Incoming(_)) if block > 0 => p[2] = F::ONE,
                Some(Wrapper::Outgoing(_)) if block + 1 < self.blocks => p[2] = -F::ONE,
                _ => {}
            }
        }
        RowMajorMatrix::new(values, CONTROLS)
    }
    /// Maps official compression witnesses into the periodic SHA trace.
    pub fn generate_trace(&self, raw: &RowMajorMatrix<F>, height: usize) -> RowMajorMatrix<F> {
        assert_eq!(height, self.height());
        assert_eq!(raw.width, NUM_SHA256_COLS);
        let blocks = self.blocks;
        assert!(raw.values.len() >= blocks * NUM_SHA256_COLS);
        let mut input = [0u32; INPUT_WORDS];
        input[16..].copy_from_slice(&SHA256_IV);
        let dummy = generate_trace_rows::<F>(vec![input], 0);
        let mut values = vec![F::ZERO; height * WIDTH];
        for (i, m) in values.chunks_exact_mut(WIDTH).enumerate() {
            let block = i / self.plan.stride;
            let local = i % self.plan.stride;
            let Some(row) = self.plan.rows.get(local) else {
                continue;
            };
            let source = if block < blocks {
                &raw.values[block * raw.width..(block + 1) * raw.width]
            } else {
                &dummy.values
            };
            for (slot, &column) in row.inputs.iter().enumerate() {
                m[slot] = source[column];
            }
            if let Some(wrapper) = row.wrapper {
                let bits = match wrapper {
                    Wrapper::Iv(_) | Wrapper::Incoming(_) => 1,
                    Wrapper::Padding(_) => 8,
                    _ => 16,
                };
                m[SLOTS] = m[..bits]
                    .iter()
                    .enumerate()
                    .fold(F::ZERO, |a, (j, &v)| a + v * F::from_u64(1 << j));
            }
        }
        RowMajorMatrix::new(values, WIDTH)
    }
    /// Evaluates the AIR polynomial constraints and lookup interactions.
    pub fn eval<AB: AirBuilder<F = F> + InteractionBuilder>(
        &self,
        b: &mut AB,
        m: &[AB::Var],
        p: &[AB::Var],
    ) {
        let q = b.periodic_values();

        let inputs: [AB::Expr; WIDTH] = core::array::from_fn(|i| m[i].into());
        let controls: [AB::Expr; CONTROLS] = core::array::from_fn(|i| p[i].into());
        let descriptor = |i: usize| -> AB::Expr { q[i].into() };
        let boolean = descriptor(self.plan.extra);

        const GATE_BOUND: usize = 35;
        assert!(self.plan.gates.len() <= GATE_BOUND);
        let values: [AB::Expr; GATE_BOUND] = core::array::from_fn(|i| {
            let Some(g) = self.plan.gates.get(i) else {
                return AB::Expr::ZERO;
            };
            let parameters: [AB::Expr; 2] = core::array::from_fn(|j| {
                let index = self.plan.params + g.parameter_offset + j;
                if index < self.plan.extra {
                    descriptor(index)
                } else {
                    AB::Expr::ZERO
                }
            });
            let value = generated_sha::evaluate(g.template, &inputs[g.offset..], &parameters);
            descriptor(2 * SLOTS + i) * value
        });
        let simple = descriptor(self.plan.extra + 1);
        let byte = descriptor(self.plan.extra + 2);
        let limb = descriptor(self.plan.extra + 3);
        let edge = descriptor(self.plan.extra + 4);
        let counts: [AB::Expr; SLOTS] = core::array::from_fn(|i| descriptor(SLOTS + i));
        let ids: [AB::Expr; SLOTS] = core::array::from_fn(descriptor);
        for i in 0..SLOTS {
            b.assert_zero(
                boolean.clone() * inputs[i].clone() * (inputs[i].clone() - AB::Expr::ONE),
            );
            b.push_interaction(
                "vmpckks.wires",
                [
                    AB::Expr::from_u8(4),
                    controls[3].clone() * F::from_usize(NUM_SHA256_COLS) + ids[i].clone(),
                    inputs[i].clone(),
                ],
                Count::bounded(counts[i].clone(), self.max_multiplicity),
            );
        }
        for value in values.into_iter().take(self.plan.gates.len()) {
            b.assert_zero(value);
        }
        let pack = |n: usize| {
            inputs[..n]
                .iter()
                .enumerate()
                .fold(AB::Expr::ZERO, |a, (i, x)| {
                    a + x.clone() * F::from_u64(1 << i)
                })
        };
        b.assert_zero(
            simple.clone() * inputs[0].clone() + byte.clone() * pack(8) + limb.clone() * pack(16)
                - (simple + byte + limb) * inputs[SLOTS].clone(),
        );
        b.assert_zero(controls[0].clone() * (inputs[SLOTS].clone() - controls[1].clone()));
        for k in 0..4 {
            b.push_interaction(
                "vmpckks.wires",
                [
                    AB::Expr::ZERO,
                    controls[5 + k].clone(),
                    inputs[2 * k].clone() + inputs[2 * k + 1].clone() * F::TWO - AB::Expr::ONE,
                ],
                Count::bounded(controls[4].clone(), 1),
            );
        }
        b.push_interaction(
            "vmpckks.wires",
            [
                AB::Expr::from_u8(3),
                controls[3].clone() * F::from_usize(16) + edge,
                inputs[SLOTS].clone(),
            ],
            Count::bounded(controls[2].clone(), 1),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::{BF, signed},
        backend::{Prepared, preflight_security},
        fri_profile::FriProfile,
        protocol::{Algorithm, Fixtures, Layout, Params, ShaImplementation, Variant},
        specialized::compile_trace,
    };
    use p3_air::BaseAir;
    use rand::SeedableRng;
    #[test]
    /// Checks batched periodic extensions against independent scalar transforms.
    fn batched_periodic_lde_matches_independent_column_transforms() {
        use p3_dft::{Radix2Dit, Radix2DitParallel, TwoAdicSubgroupDft};
        use p3_field::Field;
        use p3_field::coset::TwoAdicMultiplicativeCoset;
        use p3_fri::TwoAdicPeriodicEvaluator;
        let trace = TwoAdicMultiplicativeCoset::<F>::new(F::ONE, 6).unwrap();
        for log_blowup in [1, 2, 3] {
            let lde = TwoAdicMultiplicativeCoset::<F>::new(F::GENERATOR, 6 + log_blowup).unwrap();
            let columns: Vec<Vec<F>> = [1, 2, 4, 8, 16, 32]
                .into_iter()
                .map(|n| (0..n).map(|i| F::from_usize(i * i + 7 * n + 13)).collect())
                .collect();
            let actual = TwoAdicPeriodicEvaluator::<Radix2DitParallel<F>>::eval_on_lde_with_dft(
                &Radix2DitParallel::default(),
                &columns,
                &trace,
                &lde,
            );
            assert_eq!(actual.width(), columns.len());
            assert_eq!(actual.height(), 32 << log_blowup);
            for (j, column) in columns.iter().enumerate() {
                let values = (0..32).map(|i| column[i % column.len()]).collect();
                let reference = Radix2Dit::<F>::default().coset_lde(
                    values,
                    log_blowup,
                    F::GENERATOR.exp_u64(2),
                );
                for (i, expected) in reference.into_iter().enumerate() {
                    assert_eq!(*actual.get(i, j), expected);
                }
            }
        }
    }

    #[test]
    /// Checks exact regeneration of frozen artifacts and evaluator source.
    fn frozen_official_artifacts_and_generated_code_reproduce() {
        assert_eq!(
            Compiler::frozen_bytes(),
            include_bytes!("sha_frozen/compiler.bin")
        );
        assert_eq!(
            PeriodicSha::frozen_bytes(),
            include_bytes!("sha_frozen/periodic.bin")
        );
        assert_eq!(
            Compiler::shared().evaluator_source(),
            include_str!("generated_sha.rs")
        );
    }
    #[test]
    /// Checks every periodic FHE relation and public schedule under both profiles.
    fn periodic_fhe_all_relations_public_schedule_and_security() {
        for n in [16, 64, 4096] {
            let mut rng = rand::rngs::StdRng::seed_from_u64(2026111201 + n as u64);
            let f = Fixtures::generate(Params::provisional(n).unwrap(), &mut rng).unwrap();
            for (mut s, w) in f
                .statements(Variant::Sha, Layout::SpecializedRadix4Periodic)
                .into_iter()
                .filter(|(s, _)| s.party == 0)
            {
                if s.key_hash.is_some() {
                    s.sha_implementation = ShaImplementation::OfficialPeriodic;
                }
                let c = compile_trace(&s, Some(&w)).unwrap();
                let p = compile_trace(&s, None).unwrap();
                assert_eq!(
                    c.air.preprocessed_trace().unwrap().values,
                    p.air.preprocessed_trace().unwrap().values
                );
                assert!(c.air.main_next_row_columns().is_empty());
                if n == 4096 {
                    assert_eq!(c.air.rows, 32768);
                    assert_eq!(
                        c.air.pre_width(),
                        if s.algorithm == Algorithm::Enc {
                            34
                        } else {
                            43
                        }
                    );
                }
                for (log_blowup, num_queries) in [(3, 100), (4, 75)] {
                    let profile = FriProfile {
                        log_blowup,
                        num_queries,
                        max_log_arity: 3,
                        log_final_poly_len: 6,
                    };
                    let sec = preflight_security(&p.air, profile).unwrap();
                    assert!(sec["ldr_non_hash_bits"].as_f64().unwrap() >= 144.);
                    if n == 16 {
                        let prover =
                            Prepared::with_profile(c.air.clone(), s.digest().unwrap(), profile)
                                .unwrap();
                        assert_eq!(sec, prover.security);
                        let wire = prover
                            .encode(prover.prove(&c.trace).unwrap(), true)
                            .unwrap();
                        let verifier =
                            Prepared::with_profile(p.air.clone(), s.digest().unwrap(), profile)
                                .unwrap();
                        let proof = verifier.decode(&wire.bytes).unwrap();
                        verifier.verify(&proof).unwrap();
                        let mut changed = s.clone();
                        if let Some(h) = &mut changed.key_hash {
                            h[0] ^= 1;
                        } else {
                            changed.session[0] ^= 1;
                        }
                        let wrong = compile_trace(&changed, None).unwrap();
                        let wrong =
                            Prepared::with_profile(wrong.air, changed.digest().unwrap(), profile)
                                .unwrap();
                        assert!(wrong.decode(&wire.bytes).is_err());
                    }
                }
                if n <= 64 {
                    let mut bad = w.clone();
                    bad.secret[0] += F::ONE;
                    assert!(compile_trace(&s, Some(&bad)).is_err());
                    if s.key_hash.is_some() {
                        let mut bad = w.clone();
                        bad.salt[0] ^= 1;
                        assert!(compile_trace(&s, Some(&bad)).is_err());
                    }
                    if s.algorithm == Algorithm::Dec {
                        let mut bad = w.clone();
                        bad.flood[0] = signed(BF + 1);
                        assert!(compile_trace(&s, Some(&bad)).is_err());
                    }
                }
            }
        }
    }
    #[test]
    /// Proves and independently verifies all retained N4096 AIRs at B8 and B16.
    fn n4096_new_airs_hiding_proof_acceptance() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(2026111219);
        let f = Fixtures::generate(Params::provisional(4096).unwrap(), &mut rng).unwrap();
        for (variant, layout) in [
            (Variant::Pk, Layout::SpecializedRadix4Fused),
            (Variant::Sha, Layout::SpecializedRadix4Periodic),
        ] {
            for (mut s, w) in f
                .statements(variant, layout)
                .into_iter()
                .filter(|(s, _)| s.party == 0)
            {
                if s.key_hash.is_some() {
                    s.sha_implementation = ShaImplementation::OfficialPeriodic;
                }
                let c = compile_trace(&s, Some(&w)).unwrap();
                for (log_blowup, num_queries) in [(3, 100), (4, 75)] {
                    let profile = FriProfile {
                        log_blowup,
                        num_queries,
                        max_log_arity: 3,
                        log_final_poly_len: 6,
                    };
                    let prover =
                        Prepared::with_profile(c.air.clone(), s.digest().unwrap(), profile)
                            .unwrap();
                    let bytes = prover
                        .encode(prover.prove(&c.trace).unwrap(), true)
                        .unwrap()
                        .bytes;
                    drop(prover);
                    let public = compile_trace(&s, None).unwrap();
                    let verifier =
                        Prepared::with_profile(public.air, s.digest().unwrap(), profile).unwrap();
                    verifier.verify(&verifier.decode(&bytes).unwrap()).unwrap();
                    eprintln!(
                        "N4096 acceptance {:?} {:?} {}: {} rows, {}/{} columns, {} bytes; RBR={}, nonhash={}",
                        variant,
                        s.algorithm,
                        profile.label(),
                        c.air.rows,
                        c.air.main_width(),
                        c.air.pre_width(),
                        bytes.len(),
                        verifier.security["proven_rbr_bits"],
                        verifier.security["ldr_non_hash_bits"]
                    );
                }
            }
        }
    }
    #[test]
    /// Rejects malformed SHA boundaries and a valid hash of a different secret.
    fn periodic_sha_false_iv_padding_chain_and_secret_binding_rejected() {
        let n = 64;
        let mut rng = rand::rngs::StdRng::seed_from_u64(5117);
        let f = Fixtures::generate(Params::provisional(n).unwrap(), &mut rng).unwrap();
        let (mut s, w) = f
            .statements(Variant::Sha, Layout::SpecializedRadix4Periodic)
            .remove(0);
        s.sha_implementation = ShaImplementation::OfficialPeriodic;
        let c = compile_trace(&s, Some(&w)).unwrap();
        let sha = c.air.official_sha.as_ref().unwrap();
        let periodic = sha.periodic.as_ref().unwrap();
        let width = c.air.main_width();
        let offset = c.air.lanes * c.air.specialized.as_ref().unwrap().main_width();
        for kind in 0..3 {
            let local = periodic
                .plan
                .rows
                .iter()
                .position(|r| match (kind, r.wrapper) {
                    (0, Some(Wrapper::Iv(_)))
                    | (1, Some(Wrapper::Padding(_)))
                    | (2, Some(Wrapper::Outgoing(_))) => true,
                    _ => false,
                })
                .unwrap();
            let mut bad = c.trace.clone();
            bad.values[local * width + offset] += F::ONE;
            assert!(crate::specialized::check_composite(&c.air, &bad).is_err());
        }

        let mut different = w.secret.clone();
        different.rotate_left(1);
        if different == w.secret {
            different[0] = -different[0] + F::ONE;
        }
        let mut other_statement = s.clone();
        other_statement.key_hash = Some(hash(&crate::arithmetic::key_message(&different, &w.salt)));
        let other = compile_trace(&other_statement, None).unwrap();
        let other_sha = other.air.official_sha.as_ref().unwrap();
        let alternate = other_sha.generate_trace(&different, &w.salt, other.air.rows);
        other_sha.check_trace(&alternate).unwrap();
        let mut bad = c.trace.clone();
        for row in 0..c.air.rows {
            bad.values[row * width + offset..row * width + width].copy_from_slice(
                &alternate.values[row * alternate.width..(row + 1) * alternate.width],
            );
        }
        assert!(
            crate::specialized::check_composite(&other.air, &bad)
                .unwrap_err()
                .contains("lookup multiset")
        );
        let profile = FriProfile {
            log_blowup: 3,
            num_queries: 100,
            max_log_arity: 3,
            log_final_poly_len: 6,
        };
        let verifier =
            Prepared::with_profile(other.air, other_statement.digest().unwrap(), profile).unwrap();
        if let Ok(mut forged) = verifier.prove(&bad) {
            forged.lookup_terminals[0].as_mut().unwrap().0 = crate::backend::E::ZERO;
            assert!(verifier.verify(&forged).is_err());
        }
    }
}
