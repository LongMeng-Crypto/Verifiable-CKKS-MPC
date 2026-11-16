use crate::arithmetic::{BF, F, signed};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngExt};
use std::cmp::Ordering;

#[derive(Default)]
struct Uniform {
    bits: Vec<bool>,
}
impl Uniform {
    /// Samples one unbiased random bit.
    fn bit(&mut self, i: usize, rng: &mut impl CryptoRng) -> bool {
        while self.bits.len() <= i {
            let word: u64 = rng.random();
            self.bits.extend((0..64).map(|j| word & (1 << j) != 0));
        }
        self.bits[i]
    }
    /// Compares a lazy random binary fraction with an exact rational value.
    fn less_rational(&mut self, mut num: u128, den: u128, rng: &mut impl CryptoRng) -> bool {
        if num == den {
            return true;
        }
        if num == 0 {
            return false;
        }
        for i in 0.. {
            num *= 2;
            let b = num >= den;
            if b {
                num -= den;
            }
            match self.bit(i, rng).cmp(&b) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                _ => {}
            }
        }
        unreachable!()
    }
    /// Compares two lazy uniform binary fractions.
    fn less_uniform(&mut self, other: &mut Self, rng: &mut impl CryptoRng) -> bool {
        for i in 0.. {
            match self.bit(i, rng).cmp(&other.bit(i, rng)) {
                Ordering::Less => return true,
                Ordering::Greater => return false,
                _ => {}
            }
        }
        unreachable!()
    }
}

/// Samples an exact Bernoulli event with a fractional exponential probability.
fn exp_fraction(num: u128, den: u128, rng: &mut impl CryptoRng) -> bool {
    let mut previous = Uniform::default();
    if !previous.less_rational(num, den, rng) {
        return true;
    }
    let mut odd = true;
    loop {
        let mut next = Uniform::default();
        if !next.less_uniform(&mut previous, rng) {
            return !odd;
        }
        odd = !odd;
        previous = next;
    }
}
/// Samples an exact Bernoulli event with a rational exponential probability.
fn exp_rational(num: u128, den: u128, rng: &mut impl CryptoRng) -> bool {
    for _ in 0..num / den {
        if !exp_fraction(1, 1, rng) {
            return false;
        }
    }
    exp_fraction(num % den, den, rng)
}
/// Samples a bounded integer using exact Gaussian rejection sampling.
pub fn discrete_gaussian(
    bound: i64,
    numerator_factor: u128,
    denominator: u128,
    rng: &mut impl CryptoRng,
) -> i64 {
    assert!(bound >= 0 && denominator > 0 && denominator <= 1 << 126);
    loop {
        let x = rng.random_range(-bound..=bound);
        let m = x.unsigned_abs() as u128;
        if exp_rational(m * m * numerator_factor, denominator, rng) {
            return x;
        }
    }
}
/// Samples one small error from the configured truncated Gaussian.
pub fn small(n: usize, rng: &mut impl CryptoRng) -> Vec<F> {
    (0..n)
        .map(|_| signed(discrete_gaussian(26, 25, 512, rng)))
        .collect()
}
/// Samples one flooding error from the configured truncated Gaussian.
pub fn flooding(n: usize, rng: &mut impl CryptoRng) -> Vec<F> {
    (0..n)
        .map(|_| signed(discrete_gaussian(BF, 1, 1 << 112, rng)))
        .collect()
}
/// Samples a uniform sparse ternary secret of the requested exact weight.
pub fn sparse(n: usize, h: usize, rng: &mut impl CryptoRng) -> Vec<F> {
    assert!(h <= n);
    let mut positions: Vec<usize> = (0..n).collect();
    positions.shuffle(rng);
    let mut out = vec![signed(0); n];
    for &j in &positions[..h] {
        out[j] = signed(if rng.random::<bool>() { 1 } else { -1 });
    }
    out
}
/// Samples independent uniform ternary coefficients.
pub fn ternary(n: usize, rng: &mut impl CryptoRng) -> Vec<F> {
    (0..n).map(|_| signed(rng.random_range(-1..=1))).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::center;
    use rand::SeedableRng;
    #[test]
    /// Checks sampler support, secret weight, and distribution regression statistics.
    fn sampler_support_weight_and_moments() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(72);
        assert_eq!(
            sparse(4096, 256, &mut rng)
                .iter()
                .filter(|&&v| center(v) != 0)
                .count(),
            256
        );
        let xs = small(30000, &mut rng);
        let mean = xs.iter().map(|&x| center(x) as f64).sum::<f64>() / xs.len() as f64;
        let variance =
            xs.iter().map(|&x| (center(x) as f64).powi(2)).sum::<f64>() / xs.len() as f64;
        assert!(xs.iter().all(|&x| center(x).abs() <= 26));
        assert!(mean.abs() < 0.10);
        assert!((variance - 10.24).abs() < 0.5);
        let xs = flooding(3000, &mut rng);
        let sigma = 2f64.powf(55.5);
        let moment = xs
            .iter()
            .map(|&x| (center(x) as f64 / sigma).powi(2))
            .sum::<f64>()
            / xs.len() as f64;
        assert!(xs.iter().all(|&x| center(x).abs() <= BF));
        assert!((moment - 1.).abs() < 0.12);
        assert!(exp_fraction(0, 1, &mut rng));
    }
}
