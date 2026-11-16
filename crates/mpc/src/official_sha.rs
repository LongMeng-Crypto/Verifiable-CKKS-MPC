use crate::{
    arithmetic::{F, TAG, key_message},
    periodic_sha::PeriodicSha,
};
use p3_air::{AirBuilder, RowWindow};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_sha256_air::{INPUT_WORDS, SHA256_IV, Sha256Cols, generate_trace_rows};
use std::{borrow::Borrow, collections::HashMap, sync::Arc};
#[derive(Clone, Debug)]
pub struct OfficialSha {
    pub secret_wires: Vec<usize>,
    pub digest: [u8; 32],
    pub blocks: usize,
    pub periodic: Option<Arc<PeriodicSha>>,
}
impl OfficialSha {
    /// Constructs the complete periodic SHA key-binding relation.
    pub fn new(secret_wires: Vec<usize>, digest: [u8; 32]) -> Self {
        let blocks = (TAG.len() + 32 + secret_wires.len() / 4 + 9).div_ceil(64);
        let periodic = Some(Arc::new(PeriodicSha::new(secret_wires.clone(), digest)));
        Self {
            secret_wires,
            digest,
            blocks,
            periodic,
        }
    }
    /// Returns the main trace width.
    pub fn width(&self) -> usize {
        self.periodic.as_ref().unwrap().width()
    }
    /// Returns the number of ordinary public preprocessing columns.
    pub fn pre_width(&self) -> usize {
        self.periodic.as_ref().unwrap().pre_width()
    }
    /// Returns the current public preprocessing row window.
    pub fn preprocessed(&self, rows: usize) -> RowMajorMatrix<F> {
        self.periodic.as_ref().unwrap().preprocessed(rows)
    }
    /// Maps official compression witnesses into the periodic SHA trace.
    pub fn generate_trace(&self, secret: &[F], salt: &[u8; 32], rows: usize) -> RowMajorMatrix<F> {
        let raw = self.compression_trace(secret, salt, self.blocks.next_power_of_two());
        self.periodic.as_ref().unwrap().generate_trace(&raw, rows)
    }
    /// Generates official SHA compression witnesses for the padded message.
    fn compression_trace(&self, secret: &[F], salt: &[u8; 32], rows: usize) -> RowMajorMatrix<F> {
        assert_eq!(secret.len(), self.secret_wires.len());
        assert!(rows.is_power_of_two() && rows >= self.blocks);
        let mut message = key_message(secret, salt);
        let bit_length = (message.len() as u64) * 8;
        message.push(0x80);
        while message.len() % 64 != 56 {
            message.push(0);
        }
        message.extend(bit_length.to_be_bytes());
        assert_eq!(message.len(), self.blocks * 64);

        let mut inputs = vec![[0u32; INPUT_WORDS]; rows];

        for input in &mut inputs {
            input[16..].copy_from_slice(&SHA256_IV);
        }
        let mut state = SHA256_IV;
        for (block, bytes) in message.chunks_exact(64).enumerate() {
            let mut input = [0u32; INPUT_WORDS];
            for (word, chunk) in input[..16].iter_mut().zip(bytes.chunks_exact(4)) {
                *word = u32::from_be_bytes(chunk.try_into().unwrap());
            }
            input[16..].copy_from_slice(&state);
            let one_row = generate_trace_rows::<F>(vec![input], 0);
            let columns: &Sha256Cols<F> = one_row.values.as_slice().borrow();
            state = core::array::from_fn(|i| {
                columns.h_out[i]
                    .iter()
                    .enumerate()
                    .fold(0u32, |word, (bit, value)| {
                        word | ((value.as_canonical_u64() as u32) << bit)
                    })
            });
            inputs[block] = input;
        }
        generate_trace_rows(inputs, 0)
    }
    /// Returns the maximum number of lookup interactions per row.
    pub fn lookup_interactions_per_row(&self) -> usize {
        self.periodic.as_ref().unwrap().interactions()
    }
    /// Evaluates the AIR polynomial constraints and lookup interactions.
    pub fn eval<AB: AirBuilder<F = F> + InteractionBuilder>(
        &self,
        builder: &mut AB,
        current: &[AB::Var],
        _next: &[AB::Var],
        prep: &[AB::Var],
    ) {
        self.periodic.as_ref().unwrap().eval(builder, current, prep);
    }
    /// Checks SHA equations, chaining, and internal variable consistency.
    pub fn check_trace(&self, trace: &RowMajorMatrix<F>) -> Result<(), String> {
        if trace.width != self.width() || !trace.values.len().is_multiple_of(trace.width) {
            return Err("invalid official SHA trace shape".into());
        }
        let rows = trace.values.len() / trace.width;
        if !rows.is_power_of_two() || rows < self.blocks {
            return Err("invalid official SHA trace height".into());
        }
        let prep = self.preprocessed(rows);
        let mut chaining = HashMap::<(u64, u64, u64), F>::new();
        for row in 0..rows {
            let current = &trace.values[row * trace.width..(row + 1) * trace.width];
            let next_row = (row + 1) % rows;
            let next = &trace.values[next_row * trace.width..(next_row + 1) * trace.width];
            let p = &prep.values[row * prep.width..(row + 1) * prep.width];
            let mut checker = RowChecker {
                main: RowWindow::from_two_rows(current, next),
                preprocessed: RowWindow::from_two_rows(p, p),
                failures: 0,
                periodic: self.periodic.as_ref().map_or_else(Vec::new, |s| {
                    s.periodic().iter().map(|p| p[row % p.len()]).collect()
                }),
                queries: vec![],
                chaining: vec![],
            };
            self.eval(&mut checker, current, next, p);
            if checker.failures != 0 {
                return Err(format!("official SHA row {row}: unsatisfied constraint"));
            }
            for (namespace, id, value, count) in checker.chaining {
                *chaining
                    .entry((
                        namespace.as_canonical_u64(),
                        id.as_canonical_u64(),
                        value.as_canonical_u64(),
                    ))
                    .or_insert(F::ZERO) += count;
            }
        }
        if chaining.values().any(|&v| v != F::ZERO) {
            return Err("official SHA chaining lookup mismatch".into());
        }
        Ok(())
    }
}
struct RowChecker<'a> {
    main: RowWindow<'a, F>,
    preprocessed: RowWindow<'a, F>,
    failures: usize,
    periodic: Vec<F>,
    queries: Vec<(usize, F)>,
    chaining: Vec<(F, F, F, F)>,
}
impl<'a> AirBuilder for RowChecker<'a> {
    type F = F;
    type Expr = F;
    type Var = F;
    type MainWindow = RowWindow<'a, F>;
    type PreprocessedWindow = RowWindow<'a, F>;
    type PublicVar = F;
    type PeriodicVar = F;

    /// Returns the periodic values for the current evaluation row.
    fn periodic_values(&self) -> &[F] {
        &self.periodic
    }
    /// Returns the current and next main trace rows.
    fn main(&self) -> Self::MainWindow {
        self.main
    }
    /// Returns the current public preprocessing row window.
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed
    }
    /// Returns the first-row selector for this evaluation.
    fn is_first_row(&self) -> F {
        F::ZERO
    }
    /// Returns the last-row selector for this evaluation.
    fn is_last_row(&self) -> F {
        F::ZERO
    }
    /// Returns the transition selector for this evaluation.
    fn is_transition(&self) -> F {
        F::ZERO
    }
    /// Records a failure when an evaluated constraint is nonzero.
    fn assert_zero<I: Into<F>>(&mut self, value: I) {
        self.failures += usize::from(value.into() != F::ZERO);
    }
}
impl InteractionBuilder for RowChecker<'_> {
    /// Adds an authenticated tuple to the shared lookup multiset.
    fn push_interaction<E: Into<F>>(
        &mut self,
        bus_name: &str,
        fields: impl IntoIterator<Item = E>,
        count: impl Into<Count<F>>,
    ) {
        let (count, _) = count.into().into_parts();
        let fields: Vec<F> = fields.into_iter().map(Into::into).collect();
        if count != F::ZERO {
            if bus_name == "vmpckks.wires"
                && fields.len() == 3
                && (fields[0] == F::from_u8(3) || fields[0] == F::from_u8(4))
            {
                if fields[0] == F::from_u8(3) {
                    self.failures += usize::from(count != F::ONE && count != -F::ONE);
                }
                self.chaining.push((fields[0], fields[1], fields[2], count));
                return;
            }
            self.failures += usize::from(
                bus_name != "vmpckks.wires"
                    || count != F::ONE
                    || fields.len() != 3
                    || fields[0] != F::ZERO,
            );
            self.queries
                .push((fields[1].as_canonical_u64() as usize, fields[2]));
        }
    }
    /// Rejects unsupported separate local lookup buses.
    fn push_local_interaction(&mut self, _tuples: impl IntoIterator<Item = (Vec<F>, Count<F>)>) {
        panic!("official SHA wrapper has no separate local bus");
    }
}
