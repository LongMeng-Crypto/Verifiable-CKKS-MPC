use crate::{arithmetic::F, official_sha::OfficialSha, specialized::SpecializedAir};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionBuilder;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::Cow;

#[derive(Clone)]
pub struct CircuitAir {
    pub rows: usize,
    pub lanes: usize,
    pub official_sha: Option<OfficialSha>,
    pub specialized: Option<SpecializedAir>,
}
impl CircuitAir {
    /// Creates a composite AIR from the shared arithmetic AIR.
    pub fn from_specialized(air: SpecializedAir) -> Self {
        Self {
            rows: air.rows,
            lanes: 1,
            official_sha: None,
            specialized: Some(air),
        }
    }
    /// Packs arithmetic rows beside the periodic SHA trace.
    pub(crate) fn with_specialized_sha(
        mut self,
        mut trace: RowMajorMatrix<F>,
        sha: OfficialSha,
        sha_trace: Option<RowMajorMatrix<F>>,
        rows: usize,
    ) -> (Self, RowMajorMatrix<F>) {
        let arithmetic = self.specialized.as_ref().unwrap();
        assert!(self.official_sha.is_none());
        assert_eq!(trace.width, arithmetic.main_width());
        let active = arithmetic.active_rows;
        let lanes = active.div_ceil(rows).max(1);
        let lane_width = arithmetic.main_width();
        let arithmetic_width = lanes * lane_width;
        let width = arithmetic_width + sha.width();
        let length = rows * width;
        trace.values.resize(length.max(trace.values.len()), F::ZERO);
        for i in (0..active).rev() {
            let destination = (i / lanes) * width + (i % lanes) * lane_width;
            trace
                .values
                .copy_within(i * lane_width..(i + 1) * lane_width, destination);
        }
        trace.values.truncate(length);
        for i in active..rows * lanes {
            let offset = (i / lanes) * width + (i % lanes) * lane_width;
            trace.values[offset..offset + lane_width].fill(F::ZERO);
        }
        if let Some(ref generated) = sha_trace {
            assert_eq!(generated.width, sha.width());
            assert_eq!(generated.values.len(), rows * generated.width);
        }
        for row in 0..rows {
            let destination = row * width + arithmetic_width;
            let output = &mut trace.values[destination..destination + sha.width()];
            if let Some(ref generated) = sha_trace {
                output
                    .copy_from_slice(&generated.values[row * sha.width()..(row + 1) * sha.width()]);
            } else {
                output.fill(F::ZERO);
            }
        }
        trace.width = width;
        self.rows = rows;
        self.lanes = lanes;
        self.official_sha = Some(sha);
        (self, trace)
    }

    /// Returns the number of active composite trace rows.
    pub fn active_rows(&self) -> usize {
        self.specialized
            .as_ref()
            .unwrap()
            .active_rows
            .div_ceil(self.lanes)
    }
    /// Returns the number of committed main columns.
    pub fn main_width(&self) -> usize {
        self.lanes * self.specialized.as_ref().unwrap().main_width()
            + self.official_sha.as_ref().map_or(0, |s| s.width())
    }
    /// Returns the number of ordinary public preprocessing columns.
    pub fn pre_width(&self) -> usize {
        self.lanes * self.specialized.as_ref().unwrap().pre_width()
            + self.official_sha.as_ref().map_or(0, |s| s.pre_width())
    }
    /// Returns the maximum number of lookup interactions per row.
    pub fn lookup_interactions_per_row(&self) -> usize {
        let a = self.specialized.as_ref().unwrap();
        let arithmetic = if a.lookup_links && a.has_hw {
            self.lanes * (a.lookup_interactions_per_row() - 2) + 2
        } else {
            self.lanes * a.lookup_interactions_per_row()
        };
        arithmetic
            + self
                .official_sha
                .as_ref()
                .map_or(0, |s| s.lookup_interactions_per_row())
    }
}
impl BaseAir<F> for CircuitAir {
    /// Returns the number of public periodic columns.
    fn num_periodic_columns(&self) -> usize {
        self.official_sha
            .as_ref()
            .map_or(0, |s| s.periodic.as_ref().unwrap().periodic().len())
    }
    /// Returns the public periodic column polynomials.
    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        self.official_sha.as_ref().map_or(Cow::Borrowed(&[]), |s| {
            Cow::Borrowed(s.periodic.as_ref().unwrap().periodic())
        })
    }
    /// Returns the main trace width.
    fn width(&self) -> usize {
        self.main_width()
    }
    /// Returns the main columns opened at the next row.
    fn main_next_row_columns(&self) -> Vec<usize> {
        self.specialized.as_ref().unwrap().main_next_row_columns()
    }
    /// Returns the public columns opened at the next row.
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    /// Returns the public preprocessing width.
    fn preprocessed_width(&self) -> usize {
        self.pre_width()
    }
    /// Constructs the verifier-reproducible public preprocessing matrix.
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let a = self.specialized.as_ref().unwrap();
        if self.official_sha.is_none() {
            return a.preprocessed_trace();
        }
        let width = self.pre_width();
        let arithmetic_width = self.lanes * a.pre_width();
        let mut matrix = vec![F::ZERO; self.rows * width];
        for i in 0..a.active_rows {
            let offset = (i / self.lanes) * width + (i % self.lanes) * a.pre_width();
            matrix[offset..offset + a.pre_width()].copy_from_slice(a.preprocessed_row(i));
        }
        let prep = self.official_sha.as_ref().unwrap().preprocessed(self.rows);
        for row in 0..self.rows {
            let start = row * width + arithmetic_width;
            matrix[start..start + prep.width]
                .copy_from_slice(&prep.values[row * prep.width..(row + 1) * prep.width]);
        }
        Some(RowMajorMatrix::new(matrix, width))
    }
}
impl<AB: AirBuilder<F = F> + InteractionBuilder> Air<AB> for CircuitAir {
    /// Evaluates the AIR polynomial constraints and lookup interactions.
    fn eval(&self, builder: &mut AB) {
        let a = self.specialized.as_ref().unwrap();
        if let Some(sha) = &self.official_sha {
            let main = builder.main();
            let m = main.current_slice();
            let prep = builder.preprocessed().clone();
            let p = prep.current_slice();
            for lane in 0..self.lanes {
                let next_accumulator = if lane + 1 < self.lanes {
                    m[(lane + 1) * a.main_width() + 1]
                } else if a.lookup_links || !a.has_hw {
                    m[lane * a.main_width() + 1]
                } else {
                    main.next_slice()[1]
                };
                a.eval_row(
                    builder,
                    &m[lane * a.main_width()..(lane + 1) * a.main_width()],
                    next_accumulator,
                    &p[lane * a.pre_width()..(lane + 1) * a.pre_width()],
                    lane == 0,
                    lane + 1 == self.lanes,
                );
            }
            let offset = self.lanes * a.main_width();
            sha.eval(
                builder,
                &m[offset..],
                &m[offset..],
                &p[self.lanes * a.pre_width()..],
            );
        } else {
            a.eval(builder);
        }
    }
}
