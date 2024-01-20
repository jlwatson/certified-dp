
/*
 * Heavily based on the tiny_ped_com library by Alex Ledger (https://github.com/aled1027/tiny_ped_com)
 */

use rand::{Rng, CryptoRng};
use curve25519_dalek::{constants, ristretto::RistrettoPoint, scalar::Scalar, traits::MultiscalarMul};

pub struct PublicParams {
    pub g: RistrettoPoint,
    pub h: RistrettoPoint,
}

pub fn setup<T: Rng + CryptoRng>(mut rng: &mut T) -> PublicParams {
    // TODO: check that g and h are correct
    let h = constants::RISTRETTO_BASEPOINT_POINT;
    let g = Scalar::random(&mut rng) * h;

    PublicParams { 
        g, h 
    }
}

pub struct Commitment(RistrettoPoint);
pub struct Proof(Scalar);
pub struct Value(Scalar);

impl Value {
    /*
    pub fn from_u64(x: u64) -> Self {
        Value(Scalar::from(x))
    }
    */

    pub fn random<T: Rng + CryptoRng>(mut rng: &mut T) -> Self {
        Value(Scalar::random(&mut rng))
    }
}

pub fn commit<T: Rng + CryptoRng>(mut rng: &mut T, val: &Value, params: &PublicParams) -> (Commitment, Proof) {
    let r = Scalar::random(&mut rng);
    let &Value(val_scalar) = val;

    let commitment = RistrettoPoint::multiscalar_mul([val_scalar, r], [params.g, params.h]);
    (Commitment(commitment), Proof(r))
}

pub fn commit_with_r(val: &Value, r: &Proof, params: &PublicParams) -> Commitment {
    let &Value(val_scalar) = val;
    let &Proof(proof_r) = r;

    let commitment = RistrettoPoint::multiscalar_mul([val_scalar, proof_r], [params.g, params.h]);
    Commitment(commitment)
}

pub fn verify(commitment: &Commitment, proof: &Proof, val: &Value, params: &PublicParams) -> bool {
    let &Commitment(commitment_point) = commitment;
    let &Proof(proof_scalar) = proof;
    let &Value(val_scalar) = val;

    let lhs = RistrettoPoint::multiscalar_mul([val_scalar, proof_scalar], [params.g, params.h]);
    lhs == commitment_point
}

pub fn add_value(val1: &Value, val2: &Value) -> Value {
    let &Value(val_scalar1) = val1;
    let &Value(val_scalar2) = val2;

    Value(val_scalar1 + val_scalar2)
}

pub fn add_comm(commitment1: &Commitment, commitment2: &Commitment) -> Commitment {
    let &Commitment(commitment_point1) = commitment1;
    let &Commitment(commitment_point2) = commitment2;

    Commitment(commitment_point1 + commitment_point2)
}

pub fn add_proof(proof1: &Proof, proof2: &Proof) -> Proof {
    let &Proof(proof_scalar1) = proof1;
    let &Proof(proof_scalar2) = proof2;

    Proof(proof_scalar1 + proof_scalar2)
}

pub fn scale_value(val: &Value, a: &Value) -> Value {
    let &Value(val_scalar) = val;
    let &Value(scalar) = a;

    Value(val_scalar * scalar)
}

pub fn scale_comm(commitment: &Commitment, a: &Value) -> Commitment {
    let &Commitment(commitment_point) = commitment;
    let &Value(scalar) = a;

    Commitment(commitment_point * scalar)
}

pub fn scale_proof(proof: &Proof, a: &Value) -> Proof {
    let &Proof(proof_scalar) = proof;
    let &Value(scalar) = a;

    Proof(proof_scalar * scalar)
}