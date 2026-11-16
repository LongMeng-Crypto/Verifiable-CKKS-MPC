use crate::{
    arithmetic::{self, F, LAST_WEIGHT, center, ntt, parse_poly},
    protocol::{Algorithm, EncMessagePolicy, Statement, Variant, Witness},
};
use p3_air::{Air, AirBuilder, BaseAir, RowWindow, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use std::{collections::HashMap, sync::Arc};

const BUILDER_WIDTH: usize = 15;
const FUSED_PRE_WIDTH: usize = 34;
const PAIR_EQUATION: usize = 33;
const TERNARY: usize = 8;
const SMALL: usize = 9;
const FLOOD: usize = 10;
const BUTTERFLY: usize = 11;
const LINEAR: usize = 12;
const TABLE: usize = 13;
const HW: usize = 14;
const HW_FIRST: usize = 15;
const HW_CONTINUE: usize = 16;
const HW_LAST: usize = 17;
const HW_TARGET: usize = 18;
const COEFF: usize = 19;
const CONSTANT: usize = 22;
const TABLE_VALUE: usize = 23;
const BYTE_NAMESPACE: u8 = 1;

type Wire = usize;

#[derive(Clone)]
pub struct SpecializedAir {
    pub rows: usize,
    pub active_rows: usize,
    pub private_ntts: usize,
    pub max_wire_multiplicity: u32,
    preprocessing: Arc<Vec<F>>,
    pub lookup_links: bool,
    pub has_small: bool,
    pub has_flood: bool,
    pub has_hw: bool,
    pub has_pair: bool,
    pub digit8_inverse: Option<F>,
}

impl SpecializedAir {
    /// Returns the number of committed main columns.
    pub fn main_width(&self) -> usize {
        if self.has_flood {
            BUILDER_WIDTH
        } else {
            BUILDER_WIDTH - 1
        }
    }
    /// Returns the number of ordinary public preprocessing columns.
    pub fn pre_width(&self) -> usize {
        FUSED_PRE_WIDTH
    }
    /// Returns the number of authenticated wire slots per arithmetic row.
    fn slots(&self) -> usize {
        8
    }
    /// Returns the fixed radix-4 preprocessing offset.
    fn shift(&self) -> usize {
        8
    }
    /// Returns the first public arithmetic coefficient column.
    fn coeff(&self) -> usize {
        COEFF + self.shift()
    }
    /// Returns the public arithmetic constant column.
    fn constant(&self) -> usize {
        CONSTANT + self.shift() + 1
    }
    /// Returns the public byte-table value column.
    fn table_value(&self) -> usize {
        TABLE_VALUE + self.shift() + 1
    }
    /// Returns the maximum number of lookup interactions per row.
    pub fn lookup_interactions_per_row(&self) -> usize {
        (if self.has_flood { 8 } else { 0 })
            + self.slots()
            + if self.lookup_links && self.has_hw {
                2
            } else {
                0
            }
    }
    /// Returns the fixed preprocessing values for one arithmetic row.
    pub(crate) fn preprocessed_row(&self, row: usize) -> &[F] {
        let width = self.pre_width();
        &self.preprocessing[row * width..(row + 1) * width]
    }

    /// Checks local arithmetic equations and the complete wire multiset.
    pub fn check(&self, trace: &RowMajorMatrix<F>) -> Result<(), String> {
        if trace.width != self.main_width() || trace.values.len() != self.rows * self.main_width() {
            return Err("specialized trace has the wrong shape".into());
        }
        let mut balance = HashMap::new();
        for row in 0..self.rows {
            let current = &trace.values[row * self.main_width()..(row + 1) * self.main_width()];
            let next_row = (row + 1) % self.rows;
            let next =
                &trace.values[next_row * self.main_width()..(next_row + 1) * self.main_width()];
            let width = self.pre_width();
            let p = &self.preprocessing[row * width..(row + 1) * width];
            let mut checker = Checker {
                main: RowWindow::from_two_rows(current, next),
                prep: RowWindow::from_two_rows(p, p),
                failures: 0,
                balance: &mut balance,
                periodic: &[],
            };
            self.eval(&mut checker);
            if checker.failures != 0 {
                return Err(format!("specialized local constraint failed at row {row}"));
            }
        }
        if balance.values().any(|&value| value != F::ZERO) {
            return Err("specialized wire/range lookup multiset mismatch".into());
        }
        Ok(())
    }
}

impl BaseAir<F> for SpecializedAir {
    /// Returns the main trace width.
    fn width(&self) -> usize {
        self.main_width()
    }
    /// Returns the public preprocessing width.
    fn preprocessed_width(&self) -> usize {
        self.pre_width()
    }
    /// Constructs the verifier-reproducible public preprocessing matrix.
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(RowMajorMatrix::new(
            (*self.preprocessing).clone(),
            self.pre_width(),
        ))
    }
    /// Returns the main columns opened at the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        if self.lookup_links || !self.has_hw {
            vec![]
        } else {
            vec![1]
        }
    }
    /// Returns the public columns opened at the next row.
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: AirBuilder<F = F> + InteractionBuilder> Air<AB> for SpecializedAir {
    /// Evaluates the AIR polynomial constraints and lookup interactions.
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let m = main.current_slice();
        let preprocessing = builder.preprocessed().clone();
        let p = preprocessing.current_slice();
        let next_accumulator = if self.lookup_links || !self.has_hw {
            m[1]
        } else {
            main.next_slice()[1]
        };
        self.eval_row(builder, m, next_accumulator, p, true, true);
    }
}

impl SpecializedAir {
    /// Evaluates one fused arithmetic row and its authenticated reads.
    pub(crate) fn eval_row<AB: AirBuilder<F = F> + InteractionBuilder>(
        &self,
        builder: &mut AB,
        m: &[AB::Var],
        next_accumulator: AB::Var,
        p: &[AB::Var],
        first_lane: bool,
        last_lane: bool,
    ) {
        let a: AB::Expr = m[0].into();
        let b: AB::Expr = m[1].into();
        let c: AB::Expr = m[2].into();

        let flag = |column: usize| -> AB::Expr { p[column + self.shift()].into() };
        let coeff = self.coeff();

        builder.assert_zero(
            flag(TERNARY) * a.clone() * (a.clone() - AB::Expr::ONE) * (a.clone() + AB::Expr::ONE),
        );
        {
            let x: AB::Expr = m[3].into();
            builder.assert_zero(
                flag(TERNARY) * x.clone() * (x.clone() - AB::Expr::ONE) * (x + AB::Expr::ONE),
            );
        }
        if self.has_hw {
            let second_square = {
                let x: AB::Expr = m[3].into();
                x.clone() * x
            };
            builder.assert_zero(
                flag(HW) * (c.clone() - b.clone() - a.clone() * a.clone() - second_square),
            );
            builder.assert_zero(flag(HW_FIRST) * b.clone());
            builder.assert_zero(flag(HW_LAST) * (c.clone() - p[HW_TARGET + self.shift()]));
            if self.lookup_links {
                let id: AB::Expr = p[0].into();
                if first_lane {
                    builder.push_interaction(
                        "vmpckks.wires",
                        [AB::Expr::from_u8(2), id.clone(), b.clone()],
                        Count::bounded(flag(HW) - flag(HW_FIRST), 1),
                    );
                }
                if last_lane {
                    builder.push_interaction(
                        "vmpckks.wires",
                        [
                            AB::Expr::from_u8(2),
                            id + AB::Expr::from_usize(2),
                            c.clone(),
                        ],
                        Count::bounded(-flag(HW_CONTINUE), 1),
                    );
                } else {
                    builder.assert_zero(
                        flag(HW_CONTINUE) * (AB::Expr::from(next_accumulator) - c.clone()),
                    );
                }
            } else {
                builder.assert_zero(
                    flag(HW_CONTINUE) * (AB::Expr::from(next_accumulator) - c.clone()),
                );
            }
        }

        let u: [AB::Expr; 4] =
            core::array::from_fn(|i| AB::Expr::from(p[coeff + i]) * AB::Expr::from(m[i]));
        let even = u[0].clone() + u[1].clone();
        let odd = u[0].clone() - u[1].clone();
        let other = u[2].clone() + u[3].clone();
        let rotated = (u[2].clone() - u[3].clone()) * arithmetic::root(2);
        let expected = [
            even.clone() + other.clone(),
            odd.clone() + rotated.clone(),
            even - other,
            odd - rotated,
        ];
        for i in 0..4 {
            builder.assert_zero(flag(BUTTERFLY) * (AB::Expr::from(m[4 + i]) - expected[i].clone()));
        }

        if let Some(inverse) = self.digit8_inverse {
            let bit1: AB::Expr = m[12].into();
            let bit2: AB::Expr = m[13].into();
            builder.assert_bool(bit1.clone());
            builder.assert_bool(bit2.clone());
            let x = (c.clone() - b.clone()) * inverse;
            let bit0 = x - bit1 * F::TWO - bit2 * F::from_u8(4);
            builder.assert_zero(flag(LINEAR) * bit0.clone() * (bit0 - AB::Expr::ONE));
        } else {
            builder.assert_zero(
                flag(LINEAR)
                    * (AB::Expr::from(p[self.constant()])
                        + AB::Expr::from(p[coeff]) * a.clone()
                        + AB::Expr::from(p[coeff + 1]) * b.clone()
                        + AB::Expr::from(p[coeff + 2]) * c.clone()),
            );
        }

        if self.has_pair {
            let flag: AB::Expr = p[PAIR_EQUATION].into();
            builder.assert_zero(
                flag.clone()
                    * (AB::Expr::from(p[coeff]) * a.clone()
                        + b.clone()
                        + AB::Expr::from(p[coeff + 2])),
            );
            builder.assert_zero(
                flag * (AB::Expr::from(p[coeff + 1]) * a.clone()
                    + AB::Expr::from(p[self.constant()]) * c.clone()
                    + AB::Expr::from(p[coeff + 3])),
            );
        }
        if self.has_small {
            let small_weights = [1u64, 2, 4, 8, 11];
            let small_magnitude = small_weights
                .iter()
                .enumerate()
                .fold(AB::Expr::ZERO, |sum, (i, &weight)| {
                    sum + AB::Expr::from(m[2 + i]) * F::from_u64(weight)
                });
            builder.assert_zero(flag(SMALL) * (b.clone() - small_magnitude));
            for i in 2..7 {
                let bit: AB::Expr = m[i].into();
                builder.assert_zero(flag(SMALL) * bit.clone() * (bit - AB::Expr::ONE));
            }
            {
                let value: AB::Expr = m[7].into();
                let magnitude: AB::Expr = m[8].into();
                let packed = (0..5).fold(AB::Expr::ZERO, |sum, i| {
                    sum + AB::Expr::from(m[9 + i]) * F::from_u64(small_weights[i])
                });
                builder.assert_zero(flag(SMALL) * (magnitude.clone() - packed));
                builder.assert_zero(
                    flag(SMALL) * (value.clone() * value - magnitude.clone() * magnitude),
                );
                for i in 9..if self.digit8_inverse.is_some() {
                    12
                } else {
                    14
                } {
                    let bit: AB::Expr = m[i].into();
                    builder.assert_zero(flag(SMALL) * bit.clone() * (bit - AB::Expr::ONE));
                }
            }
            builder.assert_zero(flag(SMALL) * (a.clone() * a.clone() - b.clone() * b.clone()));
        }
        if self.has_flood {
            let mut flood_magnitude = AB::Expr::ZERO;
            for i in 0..7 {
                flood_magnitude += AB::Expr::from(m[2 + i]) * F::from_u64(1u64 << (8 * i));
                builder.push_interaction(
                    "vmpckks.wires",
                    [
                        AB::Expr::from_u8(BYTE_NAMESPACE),
                        m[2 + i].into(),
                        AB::Expr::ZERO,
                    ],
                    Count::bounded(flag(FLOOD), 1),
                );
            }
            for (column, weight) in [(9, 1u64 << 56), (10, 1u64 << 57), (11, LAST_WEIGHT)] {
                let bit: AB::Expr = m[column].into();
                flood_magnitude += bit.clone() * F::from_u64(weight);
                builder.assert_zero(flag(FLOOD) * bit.clone() * (bit - AB::Expr::ONE));
            }
            builder.assert_zero(flag(FLOOD) * (b.clone() - flood_magnitude));
            builder.assert_zero(flag(FLOOD) * (a.clone() * a - b.clone() * b));

            builder.assert_zero(flag(TABLE) * (AB::Expr::from(m[0]) - p[self.table_value()]));
            builder.assert_zero((AB::Expr::ONE - flag(TABLE)) * AB::Expr::from(m[14]));
            builder.push_interaction(
                "vmpckks.wires",
                [
                    AB::Expr::from_u8(BYTE_NAMESPACE),
                    m[0].into(),
                    AB::Expr::ZERO,
                ],
                Count::provided(-flag(TABLE) * AB::Expr::from(m[14])),
            );
        }
        for slot in 0..self.slots() {
            builder.push_interaction(
                "vmpckks.wires",
                [AB::Expr::ZERO, p[slot].into(), m[slot].into()],
                Count::bounded(p[self.slots() + slot].into(), self.max_wire_multiplicity),
            );
        }
    }
}

impl SpecializedAir {}

struct Builder {
    main: Vec<[F; BUILDER_WIDTH]>,
    prep: Vec<[F; FUSED_PRE_WIDTH]>,
    lookup_links: bool,
    values: Vec<F>,
    fanout: Vec<u32>,
    definitions: Vec<(usize, usize)>,
    byte_counts: [usize; 256],
    needs_byte_table: bool,
    ntts: usize,
    has_small: bool,
    has_hw: bool,
    has_flood: bool,
    has_pair: bool,
    digit8_inverse: Option<F>,
}

impl Builder {
    #[cfg(test)]
    /// Defines an unconstrained test input for the independent NTT oracle.
    fn free(&mut self, value: F) -> Wire {
        let row = self.row(None);
        self.define(row, 0, value)
    }

    /// Creates the fused radix-4 arithmetic trace builder.
    fn new() -> Self {
        Self {
            lookup_links: false,
            main: vec![],
            prep: vec![],
            values: vec![],
            fanout: vec![],
            definitions: vec![],
            byte_counts: [0; 256],
            needs_byte_table: false,
            ntts: 0,
            has_small: true,
            has_hw: true,
            has_flood: true,
            has_pair: false,
            digit8_inverse: None,
        }
    }
    /// Allocates an arithmetic row with its fixed operation selector.
    fn row(&mut self, kind: Option<usize>) -> usize {
        let row = self.main.len();
        self.main.push([F::ZERO; BUILDER_WIDTH]);
        self.prep.push([F::ZERO; FUSED_PRE_WIDTH]);
        if let Some(flag) = kind {
            self.prep[row][flag + 8] = F::ONE;
        }
        row
    }
    /// Defines a private wire at its canonical trace cell.
    fn define(&mut self, row: usize, slot: usize, value: F) -> Wire {
        let wire = self.values.len();
        self.values.push(value);
        self.fanout.push(0);
        self.definitions.push((row, slot));
        self.prep[row][slot] = F::from_usize(wire);
        self.main[row][slot] = value;
        wire
    }
    /// Reads an existing wire and updates its public fanout.
    fn read(&mut self, row: usize, slot: usize, wire: Wire) {
        self.prep[row][slot] = F::from_usize(wire);
        self.prep[row][8 + slot] = F::ONE;
        self.main[row][slot] = self.values[wire];
        self.fanout[wire] = self.fanout[wire].checked_add(1).unwrap();
    }

    /// Constrains paired ternary coefficients and optional exact Hamming weight.
    fn ternary(&mut self, values: &[F], h: Option<usize>) -> Vec<Wire> {
        let mut accumulator = F::ZERO;
        values
            .chunks(2)
            .enumerate()
            .flat_map(|(i, pair)| {
                let row = self.row(Some(TERNARY));
                if let Some(target) = h {
                    for (flag, set) in [
                        (HW, true),
                        (HW_FIRST, i == 0),
                        (HW_CONTINUE, 2 * i + 2 < values.len()),
                        (HW_LAST, 2 * i + 2 == values.len()),
                    ] {
                        self.prep[row][flag + 8] = F::from_bool(set);
                    }
                    self.prep[row][HW_TARGET + 8] = F::from_usize(target);
                    self.main[row][1] = accumulator;
                    accumulator += pair[0] * pair[0] + pair[1] * pair[1];
                    self.main[row][2] = accumulator;
                }
                [self.define(row, 0, pair[0]), self.define(row, 3, pair[1])]
            })
            .collect()
    }
    /// Builds exact small-error or flooding range witnesses.
    fn range(&mut self, values: &[F], flood: bool) -> Vec<Wire> {
        if !flood {
            return values
                .chunks(2)
                .flat_map(|pair| {
                    let row = self.row(Some(SMALL));
                    let mut wires = Vec::with_capacity(2);
                    for (lane, &value) in pair.iter().enumerate() {
                        wires.push(self.define(row, if lane == 0 { 0 } else { 7 }, value));
                        let magnitude = center(value).unsigned_abs();
                        let last = magnitude > 15;
                        let rest = if last {
                            magnitude.saturating_sub(11)
                        } else {
                            magnitude
                        };
                        let start = if lane == 0 { 2 } else { 9 };
                        for bit in 0..4 {
                            self.main[row][start + bit] = F::from_u64((rest >> bit) & 1);
                        }
                        self.main[row][start + 4] = F::from_bool(last);
                        self.main[row][if lane == 0 { 1 } else { 8 }] =
                            F::from_u64((rest & 15) + 11 * u64::from(last));
                    }
                    wires
                })
                .collect();
        }
        values
            .iter()
            .map(|&value| {
                let row = self.row(Some(FLOOD));
                let wire = self.define(row, 0, value);
                let magnitude = center(value).unsigned_abs();

                self.needs_byte_table = true;
                let last = magnitude > (1u64 << 58) - 1;
                let rest = if last {
                    magnitude.saturating_sub(LAST_WEIGHT)
                } else {
                    magnitude
                };
                let mut encoded = 0u64;
                for i in 0..7 {
                    let byte = ((rest >> (8 * i)) & 255) as usize;
                    self.main[row][2 + i] = F::from_usize(byte);
                    self.byte_counts[byte] += 1;
                    encoded += (byte as u64) << (8 * i);
                }
                for (column, bit) in [(9, 56), (10, 57)] {
                    let set = rest & (1u64 << bit) != 0;
                    self.main[row][column] = F::from_bool(set);
                    encoded += u64::from(set) << bit;
                }
                self.main[row][11] = F::from_bool(last);
                encoded += u64::from(last) * LAST_WEIGHT;
                self.main[row][1] = F::from_u64(encoded);

                wire
            })
            .collect()
    }

    /// Computes the negacyclic number-theoretic transform.
    fn ntt(&mut self, input: &[Wire]) -> Vec<Wire> {
        self.ntts += 1;
        self.ntt_radix4(input)
    }

    /// Constrains a four-input negacyclic NTT butterfly.
    fn butterfly4(&mut self, input: [Wire; 4], coeffs: [F; 4]) -> [Wire; 4] {
        let row = self.row(Some(BUTTERFLY));
        let mut u = [F::ZERO; 4];
        for i in 0..4 {
            self.read(row, i, input[i]);
            self.prep[row][COEFF + 8 + i] = coeffs[i];
            u[i] = coeffs[i] * self.values[input[i]];
        }
        let even = u[0] + u[1];
        let odd = u[0] - u[1];
        let other = u[2] + u[3];
        let rotated = (u[2] - u[3]) * arithmetic::root(2);
        let outputs = [even + other, odd + rotated, even - other, odd - rotated];
        core::array::from_fn(|i| self.define(row, 4 + i, outputs[i]))
    }
    /// Builds every radix-4 NTT stage and any final radix-2 stage.
    fn ntt_radix4(&mut self, input: &[Wire]) -> Vec<Wire> {
        let n = input.len();
        let psi = arithmetic::root(n);
        let omega = psi.square();
        let mut wires: Vec<_> = (0..n)
            .map(|i| input[arithmetic::bit_reverse(i, n.ilog2())])
            .collect();
        let mut len = 4;
        while len <= n {
            let quarter = len / 4;
            let step = omega.exp_u64((n / len) as u64);
            for start in (0..n).step_by(len) {
                let mut beta = F::ONE;
                for j in 0..quarter {
                    let alpha = beta.square();
                    let positions = core::array::from_fn::<_, 4, _>(|k| start + j + k * quarter);
                    let mut coeffs = [F::ONE, alpha, beta, alpha * beta];
                    if len == 4 {
                        for k in 0..4 {
                            let original = arithmetic::bit_reverse(positions[k], n.ilog2());
                            coeffs[k] *= psi.exp_u64(original as u64);
                        }
                    }
                    let out = self.butterfly4(positions.map(|i| wires[i]), coeffs);
                    for k in 0..4 {
                        wires[positions[k]] = out[k];
                    }
                    beta *= step;
                }
            }
            len *= 4;
        }

        if n.ilog2() % 2 == 1 {
            let step = omega;
            let mut twiddle = F::ONE;
            for j in 0..n / 2 {
                let u = wires[j];
                let v = wires[j + n / 2];
                let out = self.butterfly4([u, v, u, u], [F::ONE, twiddle, F::ZERO, F::ZERO]);
                wires[j] = out[0];
                wires[j + n / 2] = out[1];
                twiddle *= step;
            }
        }
        wires
    }

    /// Constrains one public ring equation in the NTT domain.
    fn equation(&mut self, a: Wire, ca: F, b: Wire, cb: F, constant: F) {
        let row = self.row(Some(LINEAR));
        self.read(row, 0, a);
        self.read(row, 1, b);
        self.prep[row][COEFF + 8] = ca;
        self.prep[row][COEFF + 1 + 8] = cb;
        self.prep[row][CONSTANT + 9] = constant;
    }
    /// Constrains two ring equations sharing one authenticated secret transform.
    fn equation_pair(&mut self, s: Wire, x: Wire, y: Wire, ca: F, cb: F, k0: F, k1: F, sign: F) {
        let row = self.row(None);
        self.prep[row][PAIR_EQUATION] = F::ONE;
        self.read(row, 0, s);
        self.read(row, 1, x);
        self.read(row, 2, y);
        self.prep[row][COEFF + 8..COEFF + 12].copy_from_slice(&[ca, cb, k0, k1]);
        self.prep[row][CONSTANT + 9] = sign;
    }
    /// Finalizes fanouts, range tables, and padded trace matrices.
    fn finish(mut self) -> (SpecializedAir, RowMajorMatrix<F>) {
        if self.needs_byte_table {
            for byte in 0..256 {
                let row = self.row(Some(TABLE));
                self.prep[row][TABLE_VALUE + 9] = F::from_usize(byte);
                self.main[row][0] = F::from_usize(byte);
                self.main[row][14] = F::from_usize(self.byte_counts[byte]);
            }
        }
        let max_wire_multiplicity = self.fanout.iter().copied().max().unwrap_or(1).max(1);
        for (wire, &(row, slot)) in self.definitions.iter().enumerate() {
            self.prep[row][8 + slot] = -F::from_u32(self.fanout[wire]);
        }
        let active_rows = self.main.len();
        let rows = active_rows.max(512).next_power_of_two();
        self.main.resize(rows, [F::ZERO; BUILDER_WIDTH]);
        self.prep.resize(rows, [F::ZERO; FUSED_PRE_WIDTH]);
        let main_width = {
            if self.has_flood {
                BUILDER_WIDTH
            } else {
                BUILDER_WIDTH - 1
            }
        };
        let mut main = self.main.into_flattened();
        if main_width != BUILDER_WIDTH {
            for row in 0..rows {
                main.copy_within(
                    row * BUILDER_WIDTH..row * BUILDER_WIDTH + main_width,
                    row * main_width,
                );
            }
            main.truncate(rows * main_width);
        }
        let trace = RowMajorMatrix::new(main, main_width);
        let preprocessing = self.prep.into_flattened();
        let air = SpecializedAir {
            rows,
            active_rows,
            private_ntts: self.ntts,
            max_wire_multiplicity,
            preprocessing: Arc::new(preprocessing),
            lookup_links: self.lookup_links,
            has_small: self.has_small,
            has_hw: self.has_hw,
            has_flood: self.has_flood,
            has_pair: self.has_pair,
            digit8_inverse: self.digit8_inverse,
        };
        (air, trace)
    }
}

/// Constructs the shared arithmetic relation from public inputs and a witness.
fn build(stmt: &Statement, witness: Option<&Witness>) -> Result<(Builder, Vec<Wire>), String> {
    stmt.validate()?;
    let n = stmt.params.n;
    let empty = Witness::empty(n);
    let w = witness.unwrap_or(&empty);
    if [&w.secret, &w.error, &w.e0, &w.e1, &w.message, &w.flood]
        .into_iter()
        .any(|v| v.len() != n)
    {
        return Err("wrong specialized witness length".into());
    }
    let mut b = Builder::new();
    if stmt.message_policy == EncMessagePolicy::Unsigned8Quadratic {
        b.digit8_inverse = Some(F::from_u64(stmt.params.kappa).inverse());
        if witness.is_some() && w.message.iter().any(|v| v.as_canonical_u64() > 7) {
            return Err("message coefficient is outside provisional unsigned digit8 domain".into());
        }
    }

    b.has_small = stmt.algorithm != Algorithm::Dec || stmt.variant == Variant::Pk;
    b.has_flood = stmt.algorithm == Algorithm::Dec;
    b.has_hw = stmt.algorithm == Algorithm::Keygen
        || (stmt.algorithm == Algorithm::Dec && stmt.variant == Variant::Pk);
    b.has_pair = stmt.algorithm == Algorithm::Enc
        || (stmt.algorithm == Algorithm::Dec && stmt.variant == Variant::Pk);

    b.lookup_links = matches!(
        stmt.layout,
        crate::protocol::Layout::SpecializedRadix4Periodic
    ) && stmt.algorithm != Algorithm::Enc;
    let secret = b.ternary(
        &w.secret,
        (stmt.algorithm == Algorithm::Keygen
            || (stmt.algorithm == Algorithm::Dec && stmt.variant == Variant::Pk))
            .then_some(stmt.params.h),
    );
    let shat = b.ntt(&secret);
    match stmt.algorithm {
        Algorithm::Keygen => {
            let error = b.range(&w.error, false);
            let ehat = b.ntt(&error);
            let ahat = ntt(&parse_poly(&stmt.a, n)?);
            let bhat = ntt(&parse_poly(&stmt.b, n)?);
            for j in 0..n {
                b.equation(shat[j], ahat[j], ehat[j], -F::ONE, bhat[j]);
            }
        }
        Algorithm::Enc => {
            let e0 = b.range(&w.e0, false);
            let e1 = b.range(&w.e1, false);
            let mu: Vec<_> = (0..n)
                .map(|i| {
                    let row = b.row(Some(LINEAR));
                    if b.digit8_inverse.is_some() {
                        let digit = w.message[i].as_canonical_u64();
                        b.main[row][12] = F::from_u64((digit >> 1) & 1);
                        b.main[row][13] = F::from_u64((digit >> 2) & 1);
                    } else {
                        b.main[row][0] = w.message[i];
                    }
                    b.read(row, 1, e0[i]);
                    b.prep[row][COEFF + 8] = F::from_u64(stmt.params.kappa);
                    b.prep[row][COEFF + 9] = F::ONE;
                    b.prep[row][COEFF + 10] = -F::ONE;
                    b.define(
                        row,
                        2,
                        F::from_u64(stmt.params.kappa) * w.message[i] + b.values[e0[i]],
                    )
                })
                .collect();
            let muhat = b.ntt(&mu);
            let ehat = b.ntt(&e1);
            let ahat = ntt(&parse_poly(&stmt.a, n)?);
            let bhat = ntt(&parse_poly(&stmt.b, n)?);
            let c0hat = ntt(&parse_poly(&stmt.c0, n)?);
            let c1hat = ntt(&parse_poly(&stmt.c1, n)?);
            for j in 0..n {
                b.equation_pair(
                    shat[j],
                    muhat[j],
                    ehat[j],
                    bhat[j],
                    ahat[j],
                    -c0hat[j],
                    -c1hat[j],
                    F::ONE,
                );
            }
        }
        Algorithm::Dec => {
            let flood = b.range(&w.flood, true);
            let rhat = b.ntt(&flood);
            let c1hat = ntt(&parse_poly(&stmt.c1, n)?);
            let dhat = ntt(&parse_poly(&stmt.d, n)?);
            if stmt.variant != Variant::Pk {
                for j in 0..n {
                    b.equation(shat[j], c1hat[j], rhat[j], F::ONE, -dhat[j]);
                }
            }
            if stmt.variant == Variant::Pk {
                let error = b.range(&w.error, false);
                let ehat = b.ntt(&error);
                let ahat = ntt(&parse_poly(&stmt.a, n)?);
                let bhat = ntt(&parse_poly(&stmt.b, n)?);
                for j in 0..n {
                    b.equation_pair(
                        shat[j],
                        rhat[j],
                        ehat[j],
                        c1hat[j],
                        ahat[j],
                        -dhat[j],
                        bhat[j],
                        -F::ONE,
                    );
                }
            }
        }
    }
    Ok((b, secret))
}

/// Compiles the supplied relation into its authenticated trace representation.
pub fn compile(
    stmt: &Statement,
    witness: Option<&Witness>,
) -> Result<(SpecializedAir, RowMajorMatrix<F>), String> {
    if stmt.key_hash.is_some() {
        return Err("use compile_trace for the composite specialized/SHA AIR".into());
    }
    Ok(build(stmt, witness)?.0.finish())
}

/// Constructs the current composite AIR and its witness or placeholder trace.
pub fn compile_trace(
    stmt: &Statement,
    witness: Option<&Witness>,
) -> Result<crate::protocol::CompiledTrace, String> {
    use crate::{circuit::CircuitAir, official_sha::OfficialSha};
    let (mut b, secret) = build(stmt, witness)?;
    let sha = if let Some(digest) = stmt.key_hash {
        for &wire in &secret {
            b.fanout[wire] = b.fanout[wire].checked_add(1).unwrap();
        }
        let sha = OfficialSha::new(secret, digest);
        let rows = sha.periodic.as_ref().unwrap().height();
        let trace = witness.map(|w| sha.generate_trace(&w.secret, &w.salt, rows));
        Some((sha, trace, rows))
    } else {
        None
    };
    let (arithmetic, trace) = b.finish();
    let private_ntts = arithmetic.private_ntts;
    let operations = arithmetic.active_rows;
    let mut air = CircuitAir::from_specialized(arithmetic);
    let (trace, sha_blocks) = if let Some((sha, sha_trace, rows)) = sha {
        let blocks = sha.blocks;
        let (combined, trace) = air.with_specialized_sha(trace, sha, sha_trace, rows);
        air = combined;
        (trace, blocks)
    } else {
        (trace, 0)
    };
    if witness.is_some() {
        if air.official_sha.is_some() {
            check_composite(&air, &trace)?;
        } else {
            air.specialized.as_ref().unwrap().check(&trace)?;
        }
    }
    Ok(crate::protocol::CompiledTrace {
        air,
        trace,
        private_ntts,
        sha_blocks,
        operations,
    })
}

/// Checks the complete arithmetic and SHA relation on one wire bus.
pub(crate) fn check_composite(
    air: &crate::circuit::CircuitAir,
    trace: &RowMajorMatrix<F>,
) -> Result<(), String> {
    if air.specialized.is_none()
        || trace.width != air.main_width()
        || trace.values.len() != air.rows * trace.width
    {
        return Err("composite specialized trace has the wrong shape".into());
    }
    let prep = air.preprocessed_trace().unwrap();
    let mut balance = HashMap::new();
    let periodic = air.periodic_columns();
    let mut periodic_values = vec![F::ZERO; periodic.len()];
    for row in 0..air.rows {
        for (value, column) in periodic_values.iter_mut().zip(periodic.iter()) {
            *value = column[row % column.len()];
        }
        let current = &trace.values[row * trace.width..(row + 1) * trace.width];
        let next_row = (row + 1) % air.rows;
        let next = &trace.values[next_row * trace.width..(next_row + 1) * trace.width];
        let p = &prep.values[row * prep.width..(row + 1) * prep.width];
        let mut checker = Checker {
            main: RowWindow::from_two_rows(current, next),
            prep: RowWindow::from_two_rows(p, p),
            failures: 0,
            balance: &mut balance,
            periodic: &periodic_values,
        };
        air.eval(&mut checker);
        if checker.failures != 0 {
            return Err(format!(
                "composite specialized local constraint failed at row {row}"
            ));
        }
    }
    if balance.values().any(|&value| value != F::ZERO) {
        return Err("composite specialized wire/range/SHA lookup multiset mismatch".into());
    }
    Ok(())
}

struct Checker<'a> {
    main: RowWindow<'a, F>,
    prep: RowWindow<'a, F>,
    failures: usize,
    balance: &'a mut HashMap<[u64; 3], F>,
    periodic: &'a [F],
}
impl<'a> AirBuilder for Checker<'a> {
    type F = F;
    type Expr = F;
    type Var = F;
    type MainWindow = RowWindow<'a, F>;
    type PreprocessedWindow = RowWindow<'a, F>;
    type PublicVar = F;
    type PeriodicVar = F;
    /// Returns the periodic values for the current evaluation row.
    fn periodic_values(&self) -> &[F] {
        self.periodic
    }
    /// Returns the current and next main trace rows.
    fn main(&self) -> Self::MainWindow {
        self.main
    }
    /// Returns the current public preprocessing row window.
    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.prep
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
impl InteractionBuilder for Checker<'_> {
    /// Adds an authenticated tuple to the shared lookup multiset.
    fn push_interaction<E: Into<F>>(
        &mut self,
        bus_name: &str,
        fields: impl IntoIterator<Item = E>,
        count: impl Into<Count<F>>,
    ) {
        let (count, bound) = count.into().into_parts();
        if count == F::ZERO {
            return;
        }
        if bound != 0 && center(count).unsigned_abs() > u64::from(bound) {
            self.failures += 1;
        }
        let fields: Vec<_> = fields.into_iter().map(Into::into).collect();
        if bus_name != "vmpckks.wires" || fields.len() != 3 {
            self.failures += 1;
            return;
        }
        let key = fields.try_into().unwrap();
        let key = <[F; 3]>::map(key, |v| v.as_canonical_u64());
        *self.balance.entry(key).or_insert(F::ZERO) += count;
    }
    /// Rejects unsupported separate local lookup buses.
    fn push_local_interaction(&mut self, _tuples: impl IntoIterator<Item = (Vec<F>, Count<F>)>) {
        panic!("specialized AIR uses one named wire bus");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        arithmetic::BF,
        protocol::{Fixtures, Layout, Params},
    };
    use rand::SeedableRng;

    #[test]
    /// Checks both packed witness lanes and both final ring equations.
    fn fused_second_lanes_and_both_final_equations_are_constrained() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(2026111221);
        let f = Fixtures::generate(Params::provisional(16).unwrap(), &mut rng).unwrap();
        for (s, w) in f
            .statements(Variant::Pk, Layout::SpecializedRadix4Fused)
            .into_iter()
            .filter(|(s, _)| s.party == 0)
        {
            let mut bad = w.clone();
            bad.secret[1] = F::from_u64(2);
            assert!(compile_trace(&s, Some(&bad)).is_err());
            for index in [0, 1] {
                let mut bad = w.clone();
                if s.algorithm == Algorithm::Enc {
                    bad.e0[index] = F::from_u64(27);
                } else {
                    bad.error[index] = F::from_u64(27);
                }
                assert!(compile_trace(&s, Some(&bad)).is_err());
            }
            if s.algorithm == Algorithm::Enc {
                let mut bad = w.clone();
                bad.e1[1] = F::from_i64(-27);
                assert!(compile_trace(&s, Some(&bad)).is_err());
                for first in [true, false] {
                    let mut changed = s.clone();
                    let p = if first {
                        &mut changed.c0
                    } else {
                        &mut changed.c1
                    };
                    p[0] = ((p[0] as u128 + 1) % crate::arithmetic::Q as u128) as u64;
                    assert!(compile_trace(&changed, Some(&w)).is_err());
                }
            } else if s.algorithm == Algorithm::Dec {
                for first in [true, false] {
                    let mut changed = s.clone();
                    let p = if first {
                        &mut changed.d
                    } else {
                        &mut changed.b
                    };
                    p[0] = ((p[0] as u128 + 1) % crate::arithmetic::Q as u128) as u64;
                    assert!(compile_trace(&changed, Some(&w)).is_err());
                }
            }
        }
    }
    #[test]
    /// Checks fused AIR geometry, exact relations, and both soundness profiles.
    fn fused_geometry_and_all_relations_match_the_reference() {
        use crate::{backend::preflight_security, fri_profile::FriProfile};
        for n in [16, 64, 4096] {
            let mut rng = rand::rngs::StdRng::seed_from_u64(2026111200 + n as u64);
            let f = Fixtures::generate(Params::provisional(n).unwrap(), &mut rng).unwrap();
            for (s, w) in f
                .statements(Variant::Pk, Layout::SpecializedRadix4Fused)
                .into_iter()
                .filter(|(s, _)| s.party == 0)
            {
                let c = compile_trace(&s, Some(&w)).unwrap();
                let p = compile_trace(&s, None).unwrap();
                assert_eq!(
                    c.air.preprocessed_trace().unwrap().values,
                    p.air.preprocessed_trace().unwrap().values
                );
                assert_eq!(
                    c.air.main_next_row_columns().is_empty(),
                    s.algorithm == Algorithm::Enc
                );
                assert_eq!(
                    c.air.lookup_interactions_per_row(),
                    if s.algorithm == Algorithm::Dec { 16 } else { 8 }
                );
                if n == 4096 {
                    assert_eq!(c.air.rows, 32768);
                    assert_eq!(
                        c.operations,
                        match s.algorithm {
                            Algorithm::Keygen => 20480,
                            Algorithm::Enc => 32768,
                            Algorithm::Dec => 30976,
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
                }
                let mut bad = c.trace.clone();
                bad.values[0] += F::from_u64(7);
                assert!(c.air.specialized.as_ref().unwrap().check(&bad).is_err());
                if n == 16 {
                    use crate::backend::Prepared;
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
                        let sec = preflight_security(&c.air, profile).unwrap();
                        assert_eq!(sec, prover.security);
                        let proof = prover.prove(&c.trace).unwrap();
                        let encoded = prover.encode(proof, true).unwrap();
                        let verifier =
                            Prepared::with_profile(p.air.clone(), s.digest().unwrap(), profile)
                                .unwrap();
                        verifier
                            .verify(&verifier.decode(&encoded.bytes).unwrap())
                            .unwrap();
                    }
                    let mut wrong = w.clone();
                    match s.algorithm {
                        Algorithm::Keygen => wrong.error[0] = F::from_u64(27),
                        Algorithm::Enc => wrong.e1[0] = F::from_u64(27),
                        Algorithm::Dec => wrong.flood[0] = F::from_i64(BF + 1),
                    }
                    assert!(compile_trace(&s, Some(&wrong)).is_err());
                }
            }
        }
    }

    #[test]
    /// Checks radix-4 transforms and rejects false authenticated copies.
    fn radix4_matches_reference_even_and_odd_heights_and_rejects_false_copies() {
        for n in [16, 32, 64, 128, 256, 4096] {
            let input: Vec<_> = (0..n).map(|i| F::from_usize(i * i + 3 * i + 17)).collect();
            let mut b = Builder::new();
            let wires: Vec<_> = input.iter().map(|&v| b.free(v)).collect();
            let output = b.ntt(&wires);
            assert_eq!(
                output.iter().map(|&i| b.values[i]).collect::<Vec<_>>(),
                ntt(&input),
                "N={n}"
            );
            let first = b
                .prep
                .iter()
                .position(|p| p[BUTTERFLY + 8] == F::ONE)
                .unwrap();
            let (air, mut trace) = b.finish();
            air.check(&trace).unwrap();
            let coefficient = air.preprocessing[first * FUSED_PRE_WIDTH + COEFF + 8];
            let row = &mut trace.values[first * air.main_width()..(first + 1) * air.main_width()];
            row[0] += F::ONE;
            for value in &mut row[4..8] {
                *value += coefficient;
            }
            assert!(air.check(&trace).unwrap_err().contains("lookup multiset"));
            if n == 16 {
                let setup = crate::backend::Prepared::new(
                    crate::circuit::CircuitAir::from_specialized(air),
                    [141; 32],
                )
                .unwrap();
                if let Ok(mut proof) = setup.prove(&trace) {
                    assert!(setup.verify(&proof).is_err());
                    proof.lookup_terminals[0].as_mut().unwrap().0 = crate::backend::E::ZERO;
                    assert!(setup.verify(&proof).is_err());
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "v2_audit_tests.rs"]
mod v2_audit_tests;
