use crate::arithmetic::F;
use p3_commit::{BatchOpening, BatchOpeningRef, HidingMmcs, Mmcs, MmcsProofGeometry};
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use rand::rngs::StdRng;
use std::sync::{Arc, Mutex};

pub type InnerMmcs = MerkleTreeHidingMmcs<
    F,
    u8,
    SerializingHasher<Sha256>,
    CompressionFunctionFromHasher<Sha256, 2, 32>,
    StdRng,
    2,
    32,
    4,
>;

pub type QueryCache = Arc<Mutex<Vec<usize>>>;

/// Creates a shared cache for public opening query coordinates.
pub fn query_cache() -> QueryCache {
    Arc::new(Mutex::new(Vec::new()))
}

/// Returns the public preprocessing query coordinates.
pub fn recorded_indices(cache: &QueryCache) -> Vec<usize> {
    cache
        .lock()
        .expect("public query recorder poisoned")
        .clone()
}

/// Clears previously recorded public query coordinates.
pub fn clear_indices(cache: &QueryCache) {
    cache
        .lock()
        .expect("public query recorder poisoned")
        .clear();
}

pub struct RecordedData<M> {
    pub inner: <InnerMmcs as Mmcs<F>>::ProverData<M>,
    pub is_public: bool,
}

pub struct RecordingMmcs {
    inner: InnerMmcs,
    public_setup: bool,
    queries: QueryCache,
}

impl RecordingMmcs {
    /// Constructs a recording wrapper for the hiding Merkle commitment scheme.
    pub fn new(inner: InnerMmcs, public_setup: bool, queries: QueryCache) -> Self {
        Self {
            inner,
            public_setup,
            queries,
        }
    }

    /// Returns the public preprocessing query coordinates.
    pub fn recorded_indices(&self) -> Vec<usize> {
        recorded_indices(&self.queries)
    }

    /// Clears previously recorded public query coordinates.
    pub fn clear_indices(&self) {
        clear_indices(&self.queries);
    }

    /// Reconstructs an opening only for authenticated public preprocessing.
    pub fn open_public_checked<M: Matrix<F>>(
        &self,
        indices: &[usize],
        data: &RecordedData<M>,
        expected_queries: usize,
    ) -> Result<(Vec<Vec<Vec<F>>>, <Self as Mmcs<F>>::MultiProof), String> {
        if !data.is_public {
            return Err("compact opening reconstruction requires public preprocessing".into());
        }
        if indices.len() != expected_queries {
            return Err("wrong public preprocessing query count".into());
        }
        let height = self.inner.get_max_height(&data.inner);
        if indices.iter().any(|&index| index >= height) {
            return Err("public preprocessing query index out of range".into());
        }

        Ok(self.inner.open_multi_batch(indices, &data.inner))
    }
}

impl Clone for RecordingMmcs {
    /// Forks the commitment state without duplicating a private random stream.
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            public_setup: self.public_setup,
            queries: self.queries.clone(),
        }
    }
}

impl Mmcs<F> for RecordingMmcs {
    type ProverData<M> = RecordedData<M>;
    type Commitment = <InnerMmcs as Mmcs<F>>::Commitment;
    type Proof = <InnerMmcs as Mmcs<F>>::Proof;
    type MultiProof = <InnerMmcs as Mmcs<F>>::MultiProof;
    type Error = <InnerMmcs as Mmcs<F>>::Error;

    /// Returns the commitment geometry used to validate opening shapes.
    fn proof_geometry(&self, log_height: usize) -> Option<MmcsProofGeometry> {
        self.inner.proof_geometry(log_height)
    }

    /// Commits the supplied matrices using the configured hiding backend.
    fn commit<M: Matrix<F>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        let (commitment, inner) = self.inner.commit(inputs);
        (
            commitment,
            RecordedData {
                inner,
                is_public: self.public_setup,
            },
        )
    }

    /// Opens a committed batch and records public preprocessing coordinates.
    fn open_batch<M: Matrix<F>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<F, Self> {
        let (values, proof) = self.inner.open_batch(index, &prover_data.inner).unpack();
        BatchOpening::new(values, proof)
    }

    /// Returns the matrices owned by the commitment data.
    fn get_matrices<'a, M: Matrix<F>>(&self, prover_data: &'a Self::ProverData<M>) -> Vec<&'a M> {
        self.inner.get_matrices(&prover_data.inner)
    }

    /// Authenticates a batch opening against the expected commitment.
    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        batch_opening: BatchOpeningRef<'_, F, Self>,
    ) -> Result<(), Self::Error> {
        let (values, proof) = batch_opening.unpack();
        self.inner.verify_batch(
            commit,
            dimensions,
            index,
            BatchOpeningRef::new(values, proof),
        )
    }

    /// Opens the requested positions across committed matrices.
    fn open_multi_batch<M: Matrix<F>>(
        &self,
        indices: &[usize],
        prover_data: &Self::ProverData<M>,
    ) -> (Vec<Vec<Vec<F>>>, Self::MultiProof) {
        if prover_data.is_public {
            *self.queries.lock().expect("public query recorder poisoned") = indices.to_vec();
        }
        self.inner.open_multi_batch(indices, &prover_data.inner)
    }

    /// Authenticates multiple matrix openings at the requested positions.
    fn verify_multi_batch<R: AsRef<[F]> + PartialEq>(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        indices: &[usize],
        opened_values: &[Vec<R>],
        proof: &Self::MultiProof,
    ) -> Result<(), Self::Error> {
        self.inner
            .verify_multi_batch(commit, dimensions, indices, opened_values, proof)
    }
}

impl HidingMmcs<F> for RecordingMmcs {}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use rand::SeedableRng;

    /// Returns the underlying hiding Merkle commitment scheme.
    fn inner(seed: u64) -> InnerMmcs {
        InnerMmcs::new(
            SerializingHasher::new(Sha256),
            CompressionFunctionFromHasher::new(Sha256),
            0,
            StdRng::seed_from_u64(seed),
        )
    }

    #[test]
    /// Checks independent salt streams and authentication across chunk boundaries.
    fn parallel_salt_streams_are_reproducible_fresh_and_authenticate_chunk_boundaries() {
        let a = inner(812).with_parallel_salts(true);
        let b = inner(812).with_parallel_salts(true);
        let height = 1 << 17;
        let matrix = RowMajorMatrix::new((0..height * 2).map(F::from_usize).collect(), 2);
        let (root, data) = a.commit(vec![matrix.clone()]);
        let (same, _) = b.commit(vec![matrix.clone()]);
        assert_eq!(root, same);
        let fork = a.clone();
        let (fresh, _) = a.commit(vec![matrix.clone()]);
        let (forked, _) = fork.commit(vec![matrix]);
        assert_ne!(root, fresh);
        assert_ne!(fresh, forked);
        let indices = [0, 65535, 65536, height - 1];
        let (values, proof) = a.open_multi_batch(&indices, &data);
        let dimensions = [Dimensions { width: 2, height }];
        b.verify_multi_batch(&root, &dimensions, &indices, &values, &proof)
            .unwrap();
        let mut bad = proof;
        bad.0[2][0][0] += F::ONE;
        assert!(
            b.verify_multi_batch(&root, &dimensions, &indices, &values, &bad)
                .is_err()
        );
    }

    #[test]
    /// Checks reconstructed public openings against the original authentication paths.
    fn public_reconstruction_preserves_original_authentication() {
        let cache = query_cache();
        let setup = RecordingMmcs::new(inner(45), true, cache.clone());
        let matrix = RowMajorMatrix::new((0..32).map(F::from_usize).collect(), 2);
        let (root, data) = setup.commit(vec![matrix]);
        let prover = RecordingMmcs::new(inner(46), false, cache);
        let indices = [0, 5, 5, 15];
        let (original_values, original_proof) = prover.open_multi_batch(&indices, &data);
        assert_eq!(prover.recorded_indices(), indices);
        let (values, proof) = setup.open_public_checked(&indices, &data, 4).unwrap();
        assert_eq!(values, original_values);
        assert_eq!(
            postcard::to_allocvec(&proof).unwrap(),
            postcard::to_allocvec(&original_proof).unwrap()
        );
        let dimensions = [Dimensions {
            width: 2,
            height: 16,
        }];
        setup
            .verify_multi_batch(&root, &dimensions, &indices, &values, &proof)
            .unwrap();

        let wrong_indices = [1, 5, 5, 15];
        let (wrong_values, wrong_proof) =
            setup.open_public_checked(&wrong_indices, &data, 4).unwrap();
        assert!(
            setup
                .verify_multi_batch(&root, &dimensions, &indices, &wrong_values, &wrong_proof)
                .is_err()
        );
        assert!(setup.open_public_checked(&indices, &data, 3).is_err());
        assert!(setup.open_public_checked(&[0, 5, 5, 16], &data, 4).is_err());
    }

    #[test]
    /// Rejects attempts to record or reconstruct private commitment data.
    fn private_data_is_neither_recorded_nor_reconstructed() {
        let cache = query_cache();
        let mmcs = RecordingMmcs::new(inner(51), false, cache);
        let matrix = RowMajorMatrix::new((0..32).map(F::from_usize).collect(), 2);
        let (_, private_data) = mmcs.commit(vec![matrix]);
        mmcs.open_multi_batch(&[0, 5], &private_data);
        assert!(mmcs.recorded_indices().is_empty());
        assert!(mmcs.open_public_checked(&[0, 5], &private_data, 2).is_err());
    }

    #[test]
    /// Checks that the upstream accessor exposes only public preprocessing.
    fn upstream_accessor_exposes_only_public_preprocessing() {
        use p3_challenger::{HashChallenger, SerializingChallenger64};
        use p3_commit::{ExtensionMmcs, Pcs, UnivariateStarkPcs};
        use p3_dft::Radix2DitParallel;
        use p3_field::extension::CubicTrinomialExtensionField;
        use p3_fri::{FriParameters, HidingFriPcs};
        type E = CubicTrinomialExtensionField<F>;
        type Ch = SerializingChallenger64<F, HashChallenger<u8, Sha256, 32>>;
        type TestPcs = HidingFriPcs<
            F,
            Radix2DitParallel<F>,
            RecordingMmcs,
            ExtensionMmcs<F, E, RecordingMmcs>,
            StdRng,
        >;
        let input = RecordingMmcs::new(inner(61), true, query_cache());
        let parameters = FriParameters {
            log_blowup: 3,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: 1,
            batch_proof_of_work_bits: 0,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
            mmcs: ExtensionMmcs::new(input.clone()),
        };
        let pcs = TestPcs::new(
            Radix2DitParallel::default(),
            input,
            parameters,
            3,
            StdRng::seed_from_u64(62),
        );
        let domain = <TestPcs as Pcs<E, Ch>>::natural_domain_for_degree(&pcs, 32);
        let matrix = RowMajorMatrix::new((0..32).map(F::from_usize).collect(), 2);
        let (_, public_data) = <TestPcs as UnivariateStarkPcs<E, Ch>>::commit_preprocessing(
            &pcs,
            vec![(domain, matrix.clone())],
        )
        .unwrap();
        assert!(public_data.public_preprocessing_data().is_some());
        let (_, private_data) =
            <TestPcs as Pcs<E, Ch>>::commit(&pcs, vec![(domain, matrix)]).unwrap();
        assert!(private_data.public_preprocessing_data().is_none());
    }
}
