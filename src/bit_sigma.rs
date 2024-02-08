use std::ops::Neg;

use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::pedersen;

#[derive(Serialize, Deserialize, Debug)]
pub struct Prover {
    b: u32,
    b_proof: Scalar,
    r_b: Scalar,
    z_not_b: Scalar,
    e_not_b: Scalar,
}

impl Default for Prover {
    fn default() -> Self {
        Prover {
            b: 0,
            b_proof: Scalar::default(),
            r_b: Scalar::default(),
            z_not_b: Scalar::default(),
            e_not_b: Scalar::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Verifier {
    pub b_comm: RistrettoPoint,
    e: Scalar,
    c_0: RistrettoPoint,
    c_1: RistrettoPoint,
}

impl Default for Verifier {
    fn default() -> Self {
        Verifier {
            b_comm: RistrettoPoint::default(),
            e: Scalar::default(),
            c_0: RistrettoPoint::default(),
            c_1: RistrettoPoint::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Commitment {
    b_comm: RistrettoPoint,
    c_0: RistrettoPoint,
    c_1: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Challenge {
    e: Scalar,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    z_0: Scalar,
    z_1: Scalar,
    e_0: Scalar,
    e_1: Scalar,
}

pub fn commit<T: Rng + CryptoRng>(rng: &mut T, pp: &pedersen::PublicParams,
                                  b: u32, b_comm: RistrettoPoint, b_proof: Scalar) -> (Prover, Commitment) {

    let (c_b, r_b) = pedersen::commit(rng, &Scalar::from(b), pp);

    let e_not_b = Scalar::random(rng);
    let (mut c_not_b, z_not_b) = 
        pedersen::commit(rng, &(Scalar::from(1 - b) * (e_not_b + Scalar::from(1 as u32))), pp);
    c_not_b += e_not_b.neg() * b_comm;

    (
        Prover {
            b,
            b_proof,
            r_b,
            z_not_b,
            e_not_b,
        },
        Commitment {
            b_comm,
            c_0: if b == 0 { c_b } else { c_not_b },
            c_1: if b == 1 { c_b } else { c_not_b },
        }
    )
}

pub fn challenge<T: Rng + CryptoRng>(rng: &mut T, comm_msg: &Commitment) -> (Verifier, Challenge) {

    let e = Scalar::random(rng);

    (
        Verifier {
            e,
            b_comm: comm_msg.b_comm,
            c_0: comm_msg.c_0,
            c_1: comm_msg.c_1,
        },
        Challenge {
            e,
        }
    )
}

pub fn response(sigma_p: &mut Prover, challenge: &Challenge) -> Response {

    let e_b = challenge.e - sigma_p.e_not_b;
    let z_b = sigma_p.r_b + (e_b * sigma_p.b_proof);

    Response{
        z_0: if sigma_p.b == 0 { z_b } else { sigma_p.z_not_b },
        z_1: if sigma_p.b == 1 { z_b } else { sigma_p.z_not_b },
        e_0: if sigma_p.b == 0 { e_b } else { sigma_p.e_not_b },
        e_1: if sigma_p.b == 1 { e_b } else { sigma_p.e_not_b },
    }
}

pub fn verify(pp: &pedersen::PublicParams, sigma_v: &mut Verifier, response: &Response) -> bool {
    if sigma_v.e != response.e_0 + response.e_1 {
        println!("ERROR: e != e0 + e1");
        return false;
    }

    if pedersen::commit_with_r(&Scalar::from(0 as u32), &response.z_0, pp) != sigma_v.c_0 + (response.e_0 * sigma_v.b_comm) {
        println!("ERROR: comm_0 != c0 + (e0 * b_comm)");
        return false;
    }

    if pedersen::commit_with_r(&(Scalar::from(1 as u32) + response.e_1), &response.z_1, pp) != sigma_v.c_1 + (response.e_1 * sigma_v.b_comm) {
        println!("ERROR: comm_1 != c1 + (e1 * b_comm)");
        return false;
    }

    true
}
