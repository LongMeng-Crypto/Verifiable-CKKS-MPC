use p3_field::PrimeCharacteristicRing;
use p3_field::{Field, PrimeField64};
pub use p3_goldilocks::Goldilocks as F;
pub const Q: u64 = 18446744069414584321;
pub const BF: i64 = 366857376337484500;
pub const LAST_WEIGHT: u64 = 78627000185772757;
pub const TAG: &[u8; 16] = b"VMPCKKS-V3-KEY\0\0";

/// Encodes a signed integer as a Goldilocks field element.
pub fn signed(x: i64) -> F {
    if x < 0 {
        -F::from_u64(x.unsigned_abs())
    } else {
        F::from_u64(x as u64)
    }
}
/// Returns the centered integer representative of a field element.
pub fn center(x: F) -> i64 {
    let v = x.as_canonical_u64();
    if v > (Q - 1) / 2 {
        -((Q - v) as i64)
    } else {
        v as i64
    }
}
/// Validates and decodes canonical polynomial coefficients.
pub fn parse_poly(x: &[u64], n: usize) -> Result<Vec<F>, String> {
    if x.len() != n || x.iter().any(|&v| v >= Q) {
        return Err("noncanonical polynomial or wrong length".into());
    }
    Ok(x.iter().map(|&v| F::from_u64(v)).collect())
}
/// Encodes canonical field coefficients for transport.
pub fn encode(x: &[F]) -> Vec<u64> {
    x.iter().map(|v| v.as_canonical_u64()).collect()
}
/// Returns a primitive negacyclic root for the requested ring degree.
pub fn root(n: usize) -> F {
    assert!(n.is_power_of_two() && (2..=4096).contains(&n));
    F::from_u64(7).exp_u64((Q - 1) / (2 * n) as u64)
}
/// Reverses the requested number of low bits.
pub fn bit_reverse(i: usize, log_n: u32) -> usize {
    i.reverse_bits() >> (usize::BITS - log_n)
}
/// Applies the in-place cyclic number-theoretic transform.
fn cyclic(x: &mut [F], omega: F) {
    let n = x.len();
    for i in 0..n {
        let j = bit_reverse(i, n.ilog2());
        if i < j {
            x.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let step = omega.exp_u64((n / len) as u64);
        for start in (0..n).step_by(len) {
            let mut w = F::ONE;
            for j in 0..len / 2 {
                let a = x[start + j];
                let b = w * x[start + j + len / 2];
                x[start + j] = a + b;
                x[start + j + len / 2] = a - b;
                w *= step;
            }
        }
        len *= 2;
    }
}
/// Computes the negacyclic number-theoretic transform.
pub fn ntt(x: &[F]) -> Vec<F> {
    let psi = root(x.len());
    let mut power = F::ONE;
    let mut y: Vec<F> = x
        .iter()
        .map(|&v| {
            let z = v * power;
            power *= psi;
            z
        })
        .collect();
    cyclic(&mut y, psi.square());
    y
}
/// Computes the inverse negacyclic number-theoretic transform.
pub fn intt(x: &[F]) -> Vec<F> {
    let psi_inv = root(x.len()).inverse();
    let n_inv = F::from_usize(x.len()).inverse();
    let mut y = x.to_vec();
    cyclic(&mut y, psi_inv.square());
    let mut power = n_inv;
    for v in &mut y {
        *v *= power;
        power *= psi_inv;
    }
    y
}
/// Multiplies two polynomials in the negacyclic ring.
pub fn mul(a: &[F], b: &[F]) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    intt(
        &ntt(a)
            .iter()
            .zip(ntt(b))
            .map(|(&a, b)| a * b)
            .collect::<Vec<_>>(),
    )
}
/// Computes an independent coefficient-wise negacyclic convolution.
pub fn naive_mul(a: &[F], b: &[F]) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    let n = a.len();
    let mut c = vec![F::ZERO; n];
    for (i, &a) in a.iter().enumerate() {
        for (j, &b) in b.iter().enumerate() {
            if i + j < n {
                c[i + j] += a * b;
            } else {
                c[i + j - n] -= a * b;
            }
        }
    }
    c
}
/// Adds corresponding polynomial coefficients.
pub fn add(a: &[F], b: &[F]) -> Vec<F> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|(&x, &y)| x + y).collect()
}
/// Computes a party public-key share from its secret and error.
pub fn keygen(a: &[F], s: &[F], e: &[F]) -> Vec<F> {
    mul(a, s).iter().zip(e).map(|(&v, &e)| e - v).collect()
}
/// Computes both ciphertext components for the supplied encryption witness.
pub fn enc(a: &[F], b: &[F], u: &[F], e0: &[F], e1: &[F], m: &[F], kappa: F) -> (Vec<F>, Vec<F>) {
    let c0 = mul(b, u)
        .iter()
        .zip(e0)
        .zip(m)
        .map(|((&v, &e), &m)| v + e + kappa * m)
        .collect();
    (c0, add(&mul(a, u), e1))
}
/// Computes a party decryption share with flooding noise.
pub fn dec(c1: &[F], s: &[F], r: &[F]) -> Vec<F> {
    add(&mul(c1, s), r)
}

/// Decodes a coefficient using the provisional digit lift.
pub fn decode_digit(v: F) -> u8 {
    let k = (Q - 1) / 8;
    (((v.as_canonical_u64() as u128 + k as u128 / 2) / k as u128) % 8) as u8
}
/// Packs ternary secret coefficients into two-bit codes.
pub fn pack_secret(s: &[F]) -> Vec<u8> {
    assert_eq!(s.len() % 4, 0);
    let mut out = vec![0; s.len() / 4];
    for (j, &x) in s.iter().enumerate() {
        let x = center(x);
        assert!((-1..=1).contains(&x));
        out[j / 4] |= ((x + 1) as u8) << (2 * (j % 4));
    }
    out
}
/// Constructs the tagged and salted secret commitment message.
pub fn key_message(s: &[F], salt: &[u8; 32]) -> Vec<u8> {
    let mut msg = TAG.to_vec();
    msg.extend(salt);
    msg.extend(pack_secret(s));
    msg
}
/// Computes the full SHA-256 digest of the supplied bytes.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    use p3_symmetric::CryptographicHasher;
    p3_sha256::Sha256.hash_iter(bytes.iter().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, SeedableRng};
    #[test]
    /// Checks centered encoding and the required NTT root orders.
    fn centered_and_roots() {
        for x in [0, 1, -1, 26, -26, BF, -BF, i64::MIN + 2147483649] {
            assert_eq!(center(signed(x)), x);
        }
        for n in [16, 64, 256, 4096] {
            assert_eq!(root(n).exp_u64(n as u64), -F::ONE);
            assert_eq!(root(n).exp_u64(2 * n as u64), F::ONE);
        }
        assert!(parse_poly(&[Q], 1).is_err());
    }
    #[test]
    /// Checks NTT multiplication against independent convolution and direct evaluation.
    fn ntt_matches_independent_convolution_and_definition() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(921);
        for n in [16, 64, 256, 4096] {
            let a: Vec<F> = (0..n).map(|_| rng.random()).collect();
            let b: Vec<F> = (0..n).map(|_| rng.random()).collect();
            assert_eq!(intt(&ntt(&a)), a);
            assert_eq!(mul(&a, &b), naive_mul(&a, &b));
            if n == 16 {
                let psi = root(n);
                for (j, &value) in ntt(&a).iter().enumerate() {
                    let z = psi.exp_u64((2 * j + 1) as u64);
                    let expected = a.iter().rev().fold(F::ZERO, |s, &a| s * z + a);
                    assert_eq!(value, expected);
                }
            }
        }
    }
    #[test]
    /// Checks ternary packing and complete SHA message sizes.
    fn packing_and_padding_sizes() {
        assert_eq!(
            pack_secret(&[signed(-1), signed(0), signed(1), signed(-1)]),
            vec![0b00100100]
        );
        assert_eq!(key_message(&vec![F::ZERO; 4096], &[0; 32]).len(), 1072);
    }
}
