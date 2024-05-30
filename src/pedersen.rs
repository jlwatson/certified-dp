/**
 * pedersen.rs
 * 
 * Base Pedersen commitment implementation.
 * Heavily based on the tiny_ped_com library by Alex Ledger (https://github.com/aled1027/tiny_ped_com).
 */

use rand::{Rng, CryptoRng};
use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};

/// Public parameters, shared from the prover to the verifier
#[derive(Clone, Debug)]
pub struct PublicParams {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

/// Generate `g` and `h` for use in the commitment scheme
pub fn setup<T: Rng + CryptoRng>(mut rng: &mut T) -> PublicParams {
    let h = constants::RISTRETTO_BASEPOINT_POINT;
    let g = Scalar::random(&mut rng) * h;

    PublicParams { 
        g, h 
    }
}

/// Generate a commitment to a value `val` with randomness `r`
#[inline]
pub fn commit<T: Rng + CryptoRng>(mut rng: &mut T, val: &Scalar, params: &PublicParams) -> (RistrettoPoint, Scalar) {
    let r = Scalar::random(&mut rng);

    let commitment = RistrettoPoint::multiscalar_mul([val, &r], [params.g, params.h]);
    (commitment, r)
}

/// Generate a commitment to a value `val` with given randomness `r`
#[inline]
pub fn commit_with_r(val: &Scalar, r: &Scalar, params: &PublicParams) -> RistrettoPoint {
    RistrettoPoint::multiscalar_mul([val, r], [params.g, params.h])
}

/// Verify that `commitment` is a correct commitment to a value `val` using the given `proof`
#[inline]
pub fn verify(commitment: &RistrettoPoint, val: &Scalar, proof: &Scalar, params: &PublicParams) -> bool {
    let lhs = RistrettoPoint::multiscalar_mul([val, proof], [params.g, params.h]);
    lhs == *commitment 
}
