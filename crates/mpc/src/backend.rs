use crate::{
    arithmetic::{F, hash},
    circuit::CircuitAir,
    compact::{self, InnerMmcs, QueryCache, RecordingMmcs},
    fri_profile::{self, FriProfile},
};
use p3_air::{AirLayout, BaseAir};
use p3_batch_stark::{
    BatchProof, PreparedBatchVerifier, ProverData, StarkInstance, prove_batch, verify_batch,
};
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeCharacteristicRing, extension::CubicTrinomialExtensionField};
use p3_fri::HidingFriPcs;
use p3_lookup::LogUpGadget;
use p3_matrix::dense::RowMajorMatrix;
use p3_sha256::Sha256;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{OpeningShape, StarkConfig};
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    ops::{Deref, DerefMut},
    sync::Mutex,
    time::Instant,
};

pub const PROFILE: &str = "vmpckks-v3-gl3-sha256-hiding-public-opening-ldr-v3";
pub type E = CubicTrinomialExtensionField<F>;
type M = RecordingMmcs;
type EM = ExtensionMmcs<F, E, M>;
type PCS = HidingFriPcs<F, Radix2DitParallel<F>, M, EM, StdRng>;
type CH = SerializingChallenger64<F, HashChallenger<u8, Sha256, 32>>;
pub type Config = StarkConfig<PCS, E, CH>;
pub type Proof = BatchProof<Config>;

const PUBLIC_BATCH: usize = 3;

/// Constructs the public or private hiding Merkle commitment scheme.
fn input_mmcs(
    context: [u8; 32],
    public_only: bool,
    profile: FriProfile,
    cache: QueryCache,
    parallel_salts: bool,
) -> M {
    let rng = if public_only {
        let mut seed = b"VMPCKKS/public-preprocessing-only/v3".to_vec();
        seed.extend(context);
        seed.extend(profile.canonical_bytes());
        StdRng::from_seed(hash(&seed))
    } else {
        crate::private_rng()
    };
    let inner = InnerMmcs::new(
        SerializingHasher::new(Sha256),
        CompressionFunctionFromHasher::new(Sha256),
        0,
        rng,
    )
    .with_parallel_salts(!public_only && parallel_salts);
    M::new(inner, public_only, cache)
}
/// Constructs the hiding STARK configuration and bound transcript.
fn config(
    context: [u8; 32],
    public_only: bool,
    profile: FriProfile,
    cache: QueryCache,
    options: ProverOptions,
    dft: Radix2DitParallel<F>,
) -> Config {
    let mmcs = input_mmcs(context, public_only, profile, cache, options.parallel_salts);
    let params = profile.parameters(EM::new(mmcs.clone()));
    let pcs_rng = if public_only {
        let mut seed = b"VMPCKKS/public-pcs-only/v3".to_vec();
        seed.extend(context);
        seed.extend(profile.canonical_bytes());
        StdRng::from_seed(hash(&seed))
    } else {
        crate::private_rng()
    };
    let pcs = PCS::new(dft, mmcs, params, 3, pcs_rng);
    let mut prefix = PROFILE.as_bytes().to_vec();
    prefix.push(0);
    prefix.extend(crate::PLONKY3_REVISION.as_bytes());
    prefix.extend(profile.canonical_bytes());
    prefix.extend(context);
    StarkConfig::new(pcs, CH::from_hasher(prefix, Sha256))
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProverOptions {
    pub parallel_salts: bool,
    pub reuse_dft: bool,
}
impl Default for ProverOptions {
    /// Returns the current default configuration.
    fn default() -> Self {
        Self {
            parallel_salts: true,
            reuse_dft: true,
        }
    }
}

pub struct Prepared {
    pub air: CircuitAir,
    pub data: ProverData<Config>,
    pub context: [u8; 32],
    pub profile: FriProfile,
    pub security: Value,
    pub setup_seconds: f64,
    pub options: ProverOptions,
    pub verifier_metadata_seconds: f64,
    verifier: Option<PreparedBatchVerifier<Config, CircuitAir>>,
    dft: Radix2DitParallel<F>,
    query_cache: QueryCache,

    capture_lock: Mutex<()>,
}

pub struct GeneratedProof {
    proof: Proof,
    public_indices: Vec<usize>,
    context: [u8; 32],
    profile: FriProfile,
}
impl GeneratedProof {
    /// Returns the proof without its local compact-opening metadata.
    pub fn into_proof(self) -> Proof {
        self.proof
    }
}
impl Deref for GeneratedProof {
    type Target = Proof;
    /// Returns the underlying generated STARK proof.
    fn deref(&self) -> &Self::Target {
        &self.proof
    }
}
impl DerefMut for GeneratedProof {
    /// Returns mutable access to the generated STARK proof.
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.proof
    }
}

pub struct EncodedProof {
    pub bytes: Vec<u8>,
    pub expanded_size_bytes: usize,
    pub public_opening_saved_bytes: usize,
}
impl Prepared {
    /// Prepares the AIR with the current B8 hiding configuration.
    pub fn new(air: CircuitAir, context: [u8; 32]) -> Result<Self, String> {
        Self::with_profile(air, context, FriProfile::default())
    }
    /// Prepares the AIR using the selected secure FRI profile.
    pub fn with_profile(
        air: CircuitAir,
        context: [u8; 32],
        profile: FriProfile,
    ) -> Result<Self, String> {
        Self::with_options(air, context, profile, ProverOptions::default())
    }
    /// Prepares the AIR with the selected prover execution options.
    pub fn with_options(
        air: CircuitAir,
        context: [u8; 32],
        profile: FriProfile,
        options: ProverOptions,
    ) -> Result<Self, String> {
        Self::with_verifier_cache(air, context, profile, options, true)
    }
    /// Prepares public commitments and optional checked verifier metadata.
    pub fn with_verifier_cache(
        air: CircuitAir,
        context: [u8; 32],
        profile: FriProfile,
        options: ProverOptions,
        verifier_cache: bool,
    ) -> Result<Self, String> {
        let start = Instant::now();
        profile.validate()?;
        preflight_security(&air, profile)?;
        let query_cache = compact::query_cache();
        let dft = Radix2DitParallel::default();
        let setup_config = config(
            context,
            true,
            profile,
            query_cache.clone(),
            options,
            dft.clone(),
        );
        let data = ProverData::from_airs_and_degrees(
            &setup_config,
            std::slice::from_ref(&air),
            &[air.rows.ilog2() as usize + 1],
        )
        .map_err(|e| format!("setup: {e:?}"))?;
        drop(setup_config);
        let security = security_report(&air, &data, profile)?;
        let metadata_start = Instant::now();
        let verifier = if verifier_cache {
            let common = p3_batch_stark::CommonData {
                preprocessed: data.common.preprocessed.as_ref().map(|p| {
                    p3_batch_stark::common::GlobalPreprocessed {
                        commitment: p.commitment.clone(),
                        instances: p.instances.clone(),
                        matrix_to_instance: p.matrix_to_instance.clone(),
                    }
                }),
                lookups: data.common.lookups.clone(),
            };
            let cfg = config(
                context,
                false,
                profile,
                query_cache.clone(),
                options,
                dft.clone(),
            );
            Some(
                PreparedBatchVerifier::new(
                    cfg,
                    vec![air.clone()],
                    common,
                    vec![air.rows.ilog2() as usize + 1],
                )
                .map_err(|e| format!("verifier metadata: {e:?}"))?,
            )
        } else {
            None
        };
        let verifier_metadata_seconds = if verifier_cache {
            metadata_start.elapsed().as_secs_f64()
        } else {
            0.0
        };

        let dft = if options.reuse_dft {
            dft
        } else {
            Radix2DitParallel::default()
        };
        Ok(Self {
            air,
            data,
            context,
            profile,
            security,
            setup_seconds: start.elapsed().as_secs_f64(),
            options,
            verifier_metadata_seconds,
            verifier,
            dft,
            query_cache,
            capture_lock: Mutex::new(()),
        })
    }
    /// Generates a fresh hiding proof and captures its public query coordinates.
    pub fn prove(&self, trace: &RowMajorMatrix<F>) -> Result<GeneratedProof, String> {
        let _capture = self
            .capture_lock
            .lock()
            .map_err(|_| "public query capture lock poisoned".to_string())?;
        compact::clear_indices(&self.query_cache);
        let dft = if self.options.reuse_dft {
            self.dft.clone()
        } else {
            Radix2DitParallel::default()
        };
        let cfg = config(
            self.context,
            false,
            self.profile,
            self.query_cache.clone(),
            self.options,
            dft,
        );
        let instances = [StarkInstance {
            air: &self.air,
            trace,
            public_values: vec![],
        }];
        let proof =
            prove_batch(&cfg, &instances, &self.data).map_err(|e| format!("prove: {e:?}"))?;
        let public_indices = compact::recorded_indices(&self.query_cache);
        if public_indices.len() != self.profile.num_queries {
            return Err("public opening query indices were not captured".into());
        }
        Ok(GeneratedProof {
            proof,
            public_indices,
            context: self.context,
            profile: self.profile,
        })
    }
    /// Verifies proof shape, transcript, lookups, and all cryptographic openings.
    pub fn verify(&self, proof: &Proof) -> Result<(), String> {
        if proof.degree_bits != vec![self.air.rows.ilog2() as usize + 1] {
            return Err("unexpected trace degree".into());
        }
        if proof.lookup_terminals.len() != 1
            || proof.lookup_terminals[0]
                .as_ref()
                .is_none_or(|t| t.0 != E::ZERO)
        {
            return Err("local wire lookup must have one zero terminal".into());
        }
        if let Some(verifier) = &self.verifier {
            return verifier
                .verify(proof, &[vec![]])
                .map_err(|e| format!("verify: {e:?}"));
        }
        let dft = if self.options.reuse_dft {
            self.dft.clone()
        } else {
            Radix2DitParallel::default()
        };
        let cfg = config(
            self.context,
            false,
            self.profile,
            self.query_cache.clone(),
            self.options,
            dft,
        );
        verify_batch(
            &cfg,
            std::slice::from_ref(&self.air),
            proof,
            &[vec![]],
            &self.data.common,
        )
        .map_err(|e| format!("verify: {e:?}"))
    }
    /// Serializes a proof with optional authenticated public-opening compaction.
    pub fn encode(
        &self,
        generated: GeneratedProof,
        compact_wire: bool,
    ) -> Result<EncodedProof, String> {
        let GeneratedProof {
            mut proof,
            public_indices,
            context,
            profile,
        } = generated;
        if context != self.context || profile != self.profile {
            return Err("generated proof belongs to a different statement/profile".into());
        }
        let expanded_size_bytes = postcard::to_allocvec(&Envelope {
            version: 3,
            profile: PROFILE.into(),
            fri_profile: self.profile,
            statement_digest: self.context,
            public_indices: None,
            proof: &proof,
        })
        .map_err(|e| e.to_string())?
        .len();
        let indices = if compact_wire {
            let indices = public_indices;
            if indices.len() != self.profile.num_queries {
                return Err("public opening query indices were not captured".into());
            }
            let batch = proof
                .opening_proof
                .1
                .input_openings
                .get_mut(PUBLIC_BATCH)
                .ok_or("missing public preprocessing opening")?;
            if batch.opened_values.len() != self.profile.num_queries {
                return Err("unexpected public preprocessing query count".into());
            }
            batch.opened_values.clear();
            batch.opening_proof.0.clear();
            batch.opening_proof.1.sibling_hashes.clear();
            Some(indices)
        } else {
            None
        };
        let bytes = postcard::to_allocvec(&Envelope {
            version: 3,
            profile: PROFILE.into(),
            fri_profile: self.profile,
            statement_digest: self.context,
            public_indices: indices,
            proof,
        })
        .map_err(|e| e.to_string())?;
        let saved = expanded_size_bytes.saturating_sub(bytes.len());
        Ok(EncodedProof {
            bytes,
            expanded_size_bytes,
            public_opening_saved_bytes: saved,
        })
    }
    /// Decodes and authenticates the proof envelope before verification.
    pub fn decode(&self, bytes: &[u8]) -> Result<Proof, String> {
        let envelope = parse_envelope(bytes, self.context)?;
        if envelope.fri_profile != self.profile {
            return Err("unexpected verifier-selected FRI profile".into());
        }
        let mut proof = envelope.proof;
        if let Some(indices) = envelope.public_indices {
            let batch = proof
                .opening_proof
                .1
                .input_openings
                .get_mut(PUBLIC_BATCH)
                .ok_or("missing compact public preprocessing slot")?;
            if !batch.opened_values.is_empty()
                || !batch.opening_proof.0.is_empty()
                || !batch.opening_proof.1.sibling_hashes.is_empty()
            {
                return Err("noncanonical compact public opening".into());
            }
            let data = self
                .data
                .prover_only
                .preprocessed_prover_data
                .as_ref()
                .ok_or("missing authenticated public preprocessing")?
                .public_preprocessing_data()
                .ok_or("private data cannot reconstruct public opening")?;
            let mmcs = input_mmcs(
                self.context,
                false,
                self.profile,
                self.query_cache.clone(),
                false,
            );
            let (values, opening) =
                mmcs.open_public_checked(&indices, data, self.profile.num_queries)?;
            batch.opened_values = values;
            batch.opening_proof = opening;
        }
        Ok(proof)
    }
}
/// Computes soundness bounds from the prepared native lookup layout.
fn security_report(
    air: &CircuitAir,
    data: &ProverData<Config>,
    profile: FriProfile,
) -> Result<Value, String> {
    security_counts(air, &data.common.lookups[0], profile)
}

/// Checks actual AIR soundness before allocating public low-degree extensions.
pub fn preflight_security(air: &CircuitAir, profile: FriProfile) -> Result<Value, String> {
    profile.validate()?;
    let gadget = LogUpGadget::new();
    let unpacked = p3_lookup::Lookups::<F>::from_air::<E, _>(air).map_err(|e| e.to_string())?;
    let log = p3_batch_stark::symbolic::get_log_num_quotient_chunks::<F, E, _, _>(
        air,
        AirLayout::from_air::<F>(air),
        air.rows,
        &unpacked,
        1,
        &gadget,
    );
    let packed = unpacked.pack_same_bus_with_degree(1 << log, |lookup| {
        gadget.constraint_degree_with_transition(lookup, 0)
    });
    security_counts(air, &packed, profile)
}
/// Counts constraints, openings, and lookup terms for soundness analysis.
fn security_counts(
    air: &CircuitAir,
    lookups: &p3_lookup::Lookups<F>,
    profile: FriProfile,
) -> Result<Value, String> {
    let layout = AirLayout::from_air::<F>(air);
    let gadget = LogUpGadget::new();
    let (base, ext) = p3_batch_stark::symbolic::get_symbolic_constraints::<F, E, _, _>(
        air, layout, lookups, &gadget,
    );
    let degree = p3_batch_stark::symbolic::get_max_constraint_degree::<F, E, _, _>(
        air, layout, air.rows, lookups, &gadget,
    );
    let log_chunks = p3_batch_stark::symbolic::get_log_num_quotient_chunks::<F, E, _, _>(
        air, layout, air.rows, lookups, 1, &gadget,
    );
    let chunks = 1 << (log_chunks + 1);
    let batched = p3_batch_stark::num_batched_openings(
        air.width(),
        !air.main_next_row_columns().is_empty(),
        air.preprocessed_width(),
        !air.preprocessed_next_row_columns().is_empty(),
        chunks,
        lookups.len(),
        3,
        OpeningShape::hiding(3),
    );
    let shape = p3_security::shape::InstanceShape {
        log_trace_length: air.rows.ilog2() as usize + 1,
        modulus_bits: 191,
        collision_resistance: 128,
        num_batched_functions: batched,
    };
    let params = p3_security::shape::StarkAirParams {
        num_constraints: base.len() + ext.len(),
        max_constraint_degree: degree,
        num_quotient_chunks: chunks,
        max_combo: 2,
    };
    if degree > 8 || air.rows < 512 {
        return Err("unsupported AIR degree or hiding height".into());
    }
    let mut report =
        fri_profile::security(&params, &shape, air.lookup_interactions_per_row(), profile)?;
    let extra = json!({"profile":PROFILE,"original_rows":air.rows,
        "active_gates":0,"active_rows":air.active_rows(),
        "main_width":air.width(),"preprocessed_width":air.preprocessed_width(),"lanes":air.lanes,
        "arithmetic_rows":air.specialized.as_ref().unwrap().active_rows,
        "arithmetic_main_columns":air.lanes*air.specialized.as_ref().unwrap().main_width(),
        "arithmetic_preprocessed_columns":air.lanes*air.specialized.as_ref().unwrap().pre_width(),
        "native_sha_rows":if air.official_sha.is_some(){air.rows}else{0},
        "ntt_radix":4,
        "lookup_links":air.specialized.as_ref().is_some_and(|s|s.lookup_links),
        "native_sha_columns":air.official_sha.as_ref().map_or(0,|s|s.width()),
        "narrow_sha":air.official_sha.as_ref().and_then(|s|s.periodic.as_ref().map(|p|p.report())),
        "periodic_columns":air.num_periodic_columns(),
        "enc_message_domain":if air.specialized.as_ref().is_some_and(|s|s.digit8_inverse.is_some()){"provisional-unsigned8-quadratic"}else{"unrestricted-or-not-applicable"},
        "main_next_columns":air.main_next_row_columns().len(),
        "permutation_extension_columns":lookups.len()+1,"constraints":params.num_constraints,
        "constraint_degree":degree,"quotient_chunks":chunks,"batched_functions":batched,
        "opening_counting":"conservative full-width next-main bound when any next columns are read",
        "lookup_interactions_per_row":air.lookup_interactions_per_row(),"public_lookup_terminal":"zero"});
    report
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    Ok(report)
}

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "P: Serialize", deserialize = "P: Deserialize<'de>"))]
pub struct Envelope<P = Proof> {
    pub version: u32,
    pub profile: String,
    pub fri_profile: FriProfile,
    pub statement_digest: [u8; 32],
    pub public_indices: Option<Vec<usize>>,
    pub proof: P,
}

/// Serializes a full proof with its authenticated context.
pub fn serialize(context: [u8; 32], proof: Proof) -> Result<Vec<u8>, String> {
    postcard::to_allocvec(&Envelope {
        version: 3,
        profile: PROFILE.into(),
        fri_profile: FriProfile::default(),
        statement_digest: context,
        public_indices: None,
        proof,
    })
    .map_err(|e| e.to_string())
}
/// Parses an envelope and checks its version, profile, and context.
fn parse_envelope(bytes: &[u8], expected: [u8; 32]) -> Result<Envelope, String> {
    let (envelope, rest): (Envelope, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|e| e.to_string())?;
    if !rest.is_empty()
        || envelope.version != 3
        || envelope.profile != PROFILE
        || envelope.statement_digest != expected
    {
        return Err("wrong statement/profile/version or trailing bytes".into());
    }
    envelope.fri_profile.validate()?;
    Ok(envelope)
}
/// Decodes a full proof with the expected context.
pub fn deserialize(bytes: &[u8], expected: [u8; 32]) -> Result<Proof, String> {
    let envelope = parse_envelope(bytes, expected)?;
    if envelope.public_indices.is_some() {
        return Err("compact proof requires authenticated Prepared data".into());
    }
    Ok(envelope.proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Constructs a deterministic valid fixture for the current proof relation.
    fn fixture() -> (CircuitAir, RowMajorMatrix<F>) {
        use crate::protocol::{
            Algorithm, EncMessagePolicy, Fixtures, Layout, Params, Variant, compile_trace,
        };
        let mut rng = StdRng::seed_from_u64(571);
        let f = Fixtures::generate_digit8(Params::provisional(16).unwrap(), &mut rng).unwrap();
        let (mut statement, witness) = f
            .statements(Variant::Pk, Layout::SpecializedRadix4Fused)
            .into_iter()
            .find(|(s, _)| s.algorithm == Algorithm::Enc)
            .unwrap();
        statement.message_policy = EncMessagePolicy::Unsigned8Quadratic;
        let c = compile_trace(&statement, Some(&witness)).unwrap();
        (c.air, c.trace)
    }

    #[test]
    /// Checks cache equivalence and rejects mutated proof shapes and openings.
    fn checked_cache_matches_original_verifier_and_rejects_proof_mutations() {
        let (air, trace) = fixture();
        let profile = FriProfile::default();
        let cached = Prepared::with_verifier_cache(
            air.clone(),
            [201; 32],
            profile,
            ProverOptions::default(),
            true,
        )
        .unwrap();
        let original =
            Prepared::with_verifier_cache(air, [201; 32], profile, ProverOptions::default(), false)
                .unwrap();
        assert!(cached.verifier_metadata_seconds > 0.0);
        assert_eq!(original.verifier_metadata_seconds, 0.0);
        let wire = cached
            .encode(cached.prove(&trace).unwrap(), true)
            .unwrap()
            .bytes;
        for prepared in [&original, &cached] {
            let mut proof = prepared.decode(&wire).unwrap();
            prepared.verify(&proof).unwrap();
            proof.degree_bits[0] += 1;
            assert!(prepared.verify(&proof).is_err());
            if let Some(v) = &prepared.verifier {
                assert!(matches!(
                    v.verify(&proof, &[vec![]]),
                    Err(p3_batch_stark::BatchVerificationError::PreparedDegreeMismatch { .. })
                ));
            }
            let mut proof = prepared.decode(&wire).unwrap();
            proof.opened_values.instances[0]
                .base_opened_values
                .trace_local
                .pop();
            assert!(prepared.verify(&proof).is_err());
            let mut proof = prepared.decode(&wire).unwrap();
            proof.opening_proof.1.input_openings[1].opened_values[0][0][0] += F::ONE;
            assert!(prepared.verify(&proof).is_err());
            let mut proof = prepared.decode(&wire).unwrap();
            proof.lookup_terminals[0].as_mut().unwrap().0 += E::ONE;
            assert!(prepared.verify(&proof).is_err());
        }
    }

    #[test]
    /// Rejects AIRs that read undeclared next-row columns during preparation.
    fn prepared_cache_rejects_undeclared_next_row_reads() {
        use p3_air::{Air, AirBuilder, WindowAccess};
        struct InvalidAir;
        impl BaseAir<F> for InvalidAir {
            /// Returns the main trace width.
            fn width(&self) -> usize {
                1
            }
            /// Returns the main columns opened at the next row.
            fn main_next_row_columns(&self) -> Vec<usize> {
                vec![]
            }
        }
        impl<AB: AirBuilder<F = F>> Air<AB> for InvalidAir {
            /// Evaluates the AIR polynomial constraints and lookup interactions.
            fn eval(&self, b: &mut AB) {
                let m = b.main();
                b.assert_zero(m.next_slice()[0]);
            }
        }
        let cache = compact::query_cache();
        let cfg = config(
            [202; 32],
            false,
            FriProfile::default(),
            cache,
            ProverOptions::default(),
            Radix2DitParallel::default(),
        );
        assert!(matches!(
            PreparedBatchVerifier::new(
                cfg,
                vec![InvalidAir],
                p3_batch_stark::CommonData::empty(1),
                vec![10]
            ),
            Err(p3_batch_stark::BatchVerificationError::Verification(
                p3_uni_stark::VerificationError::UndeclaredNextRowRead { .. }
            ))
        ));
    }

    #[test]
    /// Checks that later proofs cannot overwrite earlier public query coordinates.
    fn public_query_capture_survives_later_proofs_and_reverse_encoding() {
        let (air, trace) = fixture();
        let setup = Prepared::new(air.clone(), [133; 32]).unwrap();
        let first = setup.prove(&trace).unwrap();
        let first_indices = first.public_indices.clone();
        let second = setup.prove(&trace).unwrap();

        compact::clear_indices(&setup.query_cache);
        let second_wire = setup.encode(second, true).unwrap();
        let first_wire = setup.encode(first, true).unwrap();
        assert_eq!(
            parse_envelope(&first_wire.bytes, [133; 32])
                .unwrap()
                .public_indices
                .unwrap(),
            first_indices
        );
        let verifier = Prepared::new(air, [133; 32]).unwrap();
        for wire in [first_wire, second_wire] {
            verifier
                .verify(&verifier.decode(&wire.bytes).unwrap())
                .unwrap();
        }
    }

    #[test]
    /// Checks independent public query capture for concurrent fresh proofs.
    fn concurrent_proofs_bind_independent_public_query_captures() {
        let (air, trace) = fixture();
        let setup = Prepared::new(air.clone(), [134; 32]).unwrap();
        let start = std::sync::Barrier::new(2);
        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| {
                start.wait();
                setup.prove(&trace).unwrap()
            });
            let second = scope.spawn(|| {
                start.wait();
                setup.prove(&trace).unwrap()
            });
            (first.join().unwrap(), second.join().unwrap())
        });
        compact::clear_indices(&setup.query_cache);
        let verifier = Prepared::new(air, [134; 32]).unwrap();
        for proof in [second, first] {
            let wire = setup.encode(proof, true).unwrap();
            verifier
                .verify(&verifier.decode(&wire.bytes).unwrap())
                .unwrap();
        }
    }
    #[test]
    /// Checks compact opening reconstruction and rejects modified coordinates.
    fn compact_public_openings_roundtrip_and_coordinate_tampering() {
        let (air, trace) = fixture();
        let setup = Prepared::new(air.clone(), [132; 32]).unwrap();
        let encoded = setup.encode(setup.prove(&trace).unwrap(), true).unwrap();
        assert!(encoded.public_opening_saved_bytes > 0);
        assert!(encoded.bytes.len() < encoded.expanded_size_bytes);
        let verifier = Prepared::new(air, [132; 32]).unwrap();
        verifier
            .verify(&verifier.decode(&encoded.bytes).unwrap())
            .unwrap();
        assert!(deserialize(&encoded.bytes, [132; 32]).is_err());
        let mut bad = parse_envelope(&encoded.bytes, [132; 32]).unwrap();
        bad.public_indices.as_mut().unwrap()[0] ^= 1;
        let bytes = postcard::to_allocvec(&bad).unwrap();
        if let Ok(proof) = verifier.decode(&bytes) {
            assert!(verifier.verify(&proof).is_err());
        }
        bad.public_indices.as_mut().unwrap().pop();
        assert!(
            verifier
                .decode(&postcard::to_allocvec(&bad).unwrap())
                .is_err()
        );
        let mut trailing = encoded.bytes.clone();
        trailing.push(0);
        assert!(verifier.decode(&trailing).is_err());
        let mut different = parse_envelope(&encoded.bytes, [132; 32]).unwrap();
        different.fri_profile.num_queries += 1;
        assert!(
            verifier
                .decode(&postcard::to_allocvec(&different).unwrap())
                .is_err()
        );
    }

    #[test]
    /// Checks fresh proof randomness and rejects context or opening substitutions.
    fn proof_freshness_context_and_opening_mutations() {
        let (air, trace) = fixture();
        let setup = Prepared::new(air.clone(), [1; 32]).unwrap();
        let p = setup.prove(&trace).unwrap();
        let bytes = serialize([1; 32], p.into_proof()).unwrap();
        let second = serialize([1; 32], setup.prove(&trace).unwrap().into_proof()).unwrap();
        assert_ne!(bytes, second);
        setup
            .verify(&deserialize(&second, [1; 32]).unwrap())
            .unwrap();
        let changed_context = Prepared::new(air, [2; 32]).unwrap();
        assert!(
            changed_context
                .verify(&deserialize(&bytes, [1; 32]).unwrap())
                .is_err()
        );
        let mut p = deserialize(&bytes, [1; 32]).unwrap();
        p.opened_values.instances[0].base_opened_values.trace_local[0] += E::ONE;
        assert!(setup.verify(&p).is_err());
        assert!(deserialize(&bytes[..bytes.len() / 2], [1; 32]).is_err());
    }
}
