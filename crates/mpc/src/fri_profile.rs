use p3_fri::FriParameters;
use p3_security::{
    air,
    assumption::SecurityAssumption,
    deep,
    error::ErrorBits,
    grinding::GrindingSites,
    logup::{LogUpAir, security_term},
    proximity::list_size_ldr_m,
    report::{ALI_LABEL, BATCH_LABEL, COLLISION_LABEL, DEEP_LABEL, LDT_LABEL, SecurityTerm},
    shape::{InstanceShape, StarkAirParams},
    stark::{proven_security_ldr_m, proven_security_report},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const TARGET_BITS: f64 = 128.0;
pub const NON_HASH_MARGIN_BITS: f64 = 144.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FriProfile {
    pub log_blowup: usize,
    pub num_queries: usize,
    pub max_log_arity: usize,
    pub log_final_poly_len: usize,
}

impl Default for FriProfile {
    /// Returns the current default configuration.
    fn default() -> Self {
        Self::b8()
    }
}

impl FriProfile {
    /// Returns the B8/Q100/fold8/final64 FRI profile.
    pub const fn b8() -> Self {
        Self {
            log_blowup: 3,
            num_queries: 100,
            max_log_arity: 3,
            log_final_poly_len: 6,
        }
    }
    /// Returns the B16/Q75/fold8/final64 FRI profile.
    pub const fn b16() -> Self {
        Self {
            log_blowup: 4,
            num_queries: 75,
            max_log_arity: 3,
            log_final_poly_len: 6,
        }
    }

    /// Rejects unsupported or inconsistent parameter selections.
    pub fn validate(self) -> Result<(), String> {
        if self != Self::b8() && self != Self::b16() {
            return Err(
                "supported profiles are B8/Q100/fold8/final64 and B16/Q75/fold8/final64".into(),
            );
        }
        Ok(())
    }

    /// Returns a readable label for the FRI profile.
    pub fn label(self) -> String {
        format!(
            "b{}-q{}-a{}-f{}",
            1usize << self.log_blowup,
            self.num_queries,
            1usize << self.max_log_arity,
            1usize << self.log_final_poly_len,
        )
    }

    /// Serializes every FRI parameter for transcript binding.
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = b"VMPCKKS/fri-profile/1\0".to_vec();
        for value in [
            self.log_blowup,
            self.num_queries,
            self.max_log_arity,
            self.log_final_poly_len,
        ] {
            bytes.extend((value as u64).to_le_bytes());
        }
        bytes
    }

    /// Builds the native FRI parameters with zero grinding.
    pub fn parameters<M>(self, mmcs: M) -> FriParameters<M> {
        FriParameters {
            log_blowup: self.log_blowup,
            log_final_poly_len: self.log_final_poly_len,
            max_log_arity: self.max_log_arity,
            num_queries: self.num_queries,
            batch_proof_of_work_bits: 0,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: 0,
            mmcs,
        }
    }
}

/// Checks proven RBR and LDR soundness including all lookup terms.
pub fn security(
    air: &StarkAirParams,
    shape: &InstanceShape,
    lookup_interactions: usize,
    profile: FriProfile,
) -> Result<Value, String> {
    profile.validate()?;
    if shape.modulus_bits != 191 || shape.collision_resistance != 128 {
        return Err("FRI profile requires the actual cubic Goldilocks challenge and SHA-256 128-bit collision cap".into());
    }
    if shape.num_batched_functions == 0
        || air.num_constraints == 0
        || air.max_constraint_degree == 0
        || air.max_constraint_degree > 8
        || air.num_quotient_chunks == 0
        || shape.log_trace_length == 0
        || shape.log_trace_length + profile.log_blowup > 32
        || profile.log_final_poly_len >= shape.log_trace_length
    {
        return Err("unsupported or degenerate AIR/FRI geometry".into());
    }

    let regime = profile.parameters(()).security_regime();
    let lookup = security_term(
        &LogUpAir {
            num_interactions: lookup_interactions,
            num_interactions_per_proof: 0,
            max_message_width: 3,
        },
        shape,
        &GrindingSites::NONE,
    );
    let extras: Vec<_> = lookup.into_iter().collect();
    let auto_report = proven_security_report(&regime, air, shape, &extras, &GrindingSites::NONE);
    let udr_non_hash = auto_report
        .udr
        .terms()
        .iter()
        .filter(|term| term.label != COLLISION_LABEL)
        .map(|term| term.bits.bits())
        .fold(f64::INFINITY, f64::min);

    let mut best: Option<(usize, f64, f64, Vec<SecurityTerm>)> = None;
    for (m, ldt) in p3_security::fri::ldr_candidates(&regime, air, shape) {
        let list_size = list_size_ldr_m(profile.log_blowup, m);
        let mut terms = vec![
            SecurityTerm::new(
                ALI_LABEL,
                air::composition_error(air.num_constraints, list_size, shape.modulus_bits),
            ),
            SecurityTerm::new(DEEP_LABEL, deep::deep_ali_error(air, shape, list_size)),
            SecurityTerm::new(LDT_LABEL, ldt),
        ];
        let mut extra_errors = Vec::with_capacity(2);
        if shape.num_batched_functions >= 2 {
            let batch = ErrorBits::from_log2(SecurityAssumption::prox_gaps_error_jb_at_m(
                shape.log_trace_length,
                profile.log_blowup,
                shape.modulus_bits,
                shape.num_batched_functions,
                m,
            ));
            terms.push(SecurityTerm::new(BATCH_LABEL, batch));
            extra_errors.push(batch);
        }
        for extra in &extras {
            terms.push(*extra);
            extra_errors.push(extra.bits);
        }
        if terms.iter().any(|term| !term.bits.bits().is_finite()) {
            continue;
        }
        let non_hash = terms
            .iter()
            .map(|term| term.bits.bits())
            .fold(f64::INFINITY, f64::min);
        let composed =
            proven_security_ldr_m(air, shape, profile.log_blowup, m, ldt, &extra_errors).bits();
        if best.as_ref().is_none_or(|candidate| non_hash > candidate.1) {
            terms.push(SecurityTerm::new(
                COLLISION_LABEL,
                ErrorBits::from_log2(shape.collision_resistance as f64),
            ));
            best = Some((m, non_hash, composed, terms));
        }
    }
    let Some((m, non_hash, composed, terms)) = best else {
        return Err("no valid proven LDR parameter for this geometry".into());
    };
    if composed < TARGET_BITS || non_hash < NON_HASH_MARGIN_BITS {
        return Err(format!(
            "FRI security policy failed for {}: proven={composed:.3}, LDR non-hash={non_hash:.3}; requires 128/144 bits",
            profile.label(),
        ));
    }

    Ok(json!({
        "fri": profile,
        "fri_label": profile.label(),
        "security_policy": "proven-LDR-128-with-144-bit-non-hash-margin",
        "proven_rbr_bits": composed,
        "ldr_non_hash_bits": non_hash,
        "udr_algebraic_bits": udr_non_hash,
        "ldr_m": m,
        "challenge_field_bits": shape.modulus_bits,
        "hash_collision_bits": shape.collision_resistance,
        "all_pow_bits": 0,
        "security_terms": terms,
        "report": {
            "udr": auto_report.udr,
            "ldr": {"regime": {"ListDecoding": {"m": m}}, "terms": terms},
        },
        "claim_scope": "upstream proven round-by-round model; full FS/session security retains documented assumptions",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    /// Checks the two supported profiles and their authenticated encodings.
    fn active_profiles_and_transcript_encoding_are_fixed() {
        for p in [FriProfile::b8(), FriProfile::b16()] {
            p.validate().unwrap();
            let mut changed = p;
            changed.num_queries -= 1;
            assert_ne!(changed.canonical_bytes(), p.canonical_bytes());
            assert!(changed.validate().is_err());
            changed = p;
            changed.max_log_arity = 2;
            assert!(changed.validate().is_err());
        }
        assert_ne!(
            FriProfile::b8().canonical_bytes(),
            FriProfile::b16().canonical_bytes()
        );
    }
}
