pub mod arithmetic;
pub mod backend;
pub mod bench;
pub mod circuit;
pub mod compact;
pub mod fri_profile;
pub mod narrow_sha;
pub mod official_sha;
pub mod protocol;
pub mod sampler;
pub mod specialized;

#[rustfmt::skip]
mod generated_sha;
pub mod periodic_sha;

#[cfg(test)]
mod enc_digit8_tests;

pub const PLONKY3_REVISION: &str = "0d803737b681774186cd283b1fd2d8e493655c82";
/// Creates a fresh operating-system-seeded private random generator.
pub fn private_rng() -> rand::rngs::StdRng {
    use rand::SeedableRng;
    rand::rngs::StdRng::from_rng(&mut rand::rng())
}
