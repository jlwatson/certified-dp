/*
 * Heavily based on the tiny_ped_com library by Alex Ledger (https://github.com/aled1027/tiny_ped_com)
 */

use rand::{Rng, CryptoRng};
use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};

#[derive(Clone, Debug)]
pub struct PublicParams {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

pub fn setup<T: Rng + CryptoRng>(mut rng: &mut T) -> PublicParams {
    let h = constants::RISTRETTO_BASEPOINT_POINT;
    let g = Scalar::random(&mut rng) * h;

    PublicParams { 
        g, h 
    }
}

pub fn commit<T: Rng + CryptoRng>(mut rng: &mut T, val: &Scalar, params: &PublicParams) -> (RistrettoPoint, Scalar) {
    let r = Scalar::random(&mut rng);

    let commitment = RistrettoPoint::multiscalar_mul([val, &r], [params.g, params.h]);
    (commitment, r)
}

pub fn commit_with_r(val: &Scalar, r: &Scalar, params: &PublicParams) -> RistrettoPoint {
    RistrettoPoint::multiscalar_mul([val, r], [params.g, params.h])
}

pub fn verify(commitment: &RistrettoPoint, proof: &Scalar, val: &Scalar, params: &PublicParams) -> bool {
    let lhs = RistrettoPoint::multiscalar_mul([val, proof], [params.g, params.h]);
    lhs == *commitment 
}
