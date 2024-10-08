/**
 * product_sigma.rs
 * 
 * Product Sigma Protocol implementation, used as a building block for the main protocol.
 * 
 * See paper A.2 "Certified Differential Privacy Construction with Dishonest Commitment Phase". This multiplication protocol is based on: 
 *     Maurer, U.: Unifying zero-knowledge proofs of knowledge.
 *     In: Preneel, B. (ed.) Progress in Cryptology – AFRICACRYPT 2009. pp. 272–286. Springer Berlin Heidelberg, Berlin, Heidelberg (2009)
 * 
 */

use curve25519_dalek::{RistrettoPoint, Scalar};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};

use crate::pedersen;

/// Prover state for the product sigma protocol.
#[derive(Serialize, Deserialize, Debug)]
pub struct Prover {
    m_1: Scalar,
    c_1: RistrettoPoint,
    r_1: Scalar,
    m_2: Scalar,
    c_2: RistrettoPoint,
    r_2: Scalar,
    m_3: Scalar,
    c_3: RistrettoPoint,
    r_3: Scalar,
    b_1: Scalar,
    b_2: Scalar,
    b_3: Scalar,
    b_4: Scalar,
    b_5: Scalar,
}

/// Zero-out values by default
impl Default for Prover {
    fn default() -> Self {
        Prover {
            m_1: Scalar::default(),
            c_1: RistrettoPoint::default(),
            r_1: Scalar::default(),
            m_2: Scalar::default(),
            c_2: RistrettoPoint::default(),
            r_2: Scalar::default(),
            m_3: Scalar::default(),
            c_3: RistrettoPoint::default(),
            r_3: Scalar::default(),
            b_1: Scalar::default(),
            b_2: Scalar::default(),
            b_3: Scalar::default(),
            b_4: Scalar::default(),
            b_5: Scalar::default(),
        }
    }
}

/// Verifier state for the product sigma protocol.
#[derive(Serialize, Deserialize, Debug)]
pub struct Verifier {
    c_1: RistrettoPoint,
    c_2: RistrettoPoint,
    c_3: RistrettoPoint,
    e: Scalar,
    c1_prime: RistrettoPoint,
    c2_prime: RistrettoPoint,
    c3_prime: RistrettoPoint,
}

/// Zero-out values by default
impl Default for Verifier {
    fn default() -> Self {
        Verifier {
            c_1: RistrettoPoint::default(),
            c_2: RistrettoPoint::default(),
            c_3: RistrettoPoint::default(),
            e: Scalar::default(),
            c1_prime: RistrettoPoint::default(),
            c2_prime: RistrettoPoint::default(),
            c3_prime: RistrettoPoint::default(),
        }
    }
}

/// Contents of commitment message from prover.
#[derive(Serialize, Deserialize, Debug)]
pub struct Commitment {
    c_1: RistrettoPoint,
    c_2: RistrettoPoint,
    c_3: RistrettoPoint,
    alpha: RistrettoPoint,
    beta: RistrettoPoint,
    gamma: RistrettoPoint,
}

/// Contents of challenge message from verifier.
#[derive(Serialize, Deserialize, Debug)]
pub struct Challenge {
    e: Scalar,
}

/// Contents of response message back from prover.
#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    z_1: Scalar,
    z_2: Scalar,
    z_3: Scalar,
    z_4: Scalar,
    z_5: Scalar,
}

/// (1) The prover commits to the three values m_1 * m_2 = m_3.
pub fn commit<T: Rng + CryptoRng>(rng: &mut T, pp: &pedersen::PublicParams,
                                  (m_1, c_1, r_1): (Scalar, RistrettoPoint, Scalar),
                                  (m_2, c_2, r_2): (Scalar, RistrettoPoint, Scalar),
                                  (m_3, c_3, r_3): (Scalar, RistrettoPoint, Scalar)) -> (Prover, Commitment) {

    let (b_1, b_2, b_3, b_4, b_5) =
        (Scalar::random(rng), Scalar::random(rng), Scalar::random(rng), Scalar::random(rng), Scalar::random(rng));

    let special_pp = pedersen::PublicParams {
        g: c_1,
        h: pp.h,
    };

    (
        Prover {
            m_1, c_1, r_1,
            m_2, c_2, r_2,
            m_3, c_3, r_3,
            b_1, b_2, b_3, b_4, b_5,
        },
        Commitment {
            c_1, c_2, c_3,
            alpha: pedersen::commit_with_r(&b_1, &b_2, pp),
            beta: pedersen::commit_with_r(&b_3, &b_4, pp),
            gamma: pedersen::commit_with_r(&b_3, &b_5, &special_pp),
        }
    )
}

/// (2) The verifier picks a random challenge `e`.
pub fn challenge<T: Rng + CryptoRng>(rng: &mut T, comm_msg: &Commitment) -> (Verifier, Challenge) {

    let e = Scalar::random(rng);

    (
        Verifier {
            c_1: comm_msg.c_1,
            c_2: comm_msg.c_2,
            c_3: comm_msg.c_3,
            e,
            c1_prime: comm_msg.alpha + (e * comm_msg.c_1),
            c2_prime: comm_msg.beta + (e * comm_msg.c_2),
            c3_prime: comm_msg.gamma + (e * comm_msg.c_3),
        },
        Challenge {
            e,
        }
    )
}

/// (3) The prover sends the response back to the verifier based on the challenge.
pub fn response(sigma_p: &mut Prover, challenge: &Challenge) -> Response {

    let z_1 = sigma_p.b_1 + (challenge.e * sigma_p.m_1);
    let z_2 = sigma_p.b_2 + (challenge.e * sigma_p.r_1);
    let z_3 = sigma_p.b_3 + (challenge.e * sigma_p.m_2);
    let z_4 = sigma_p.b_4 + (challenge.e * sigma_p.r_2);
    let z_5 = sigma_p.b_5 + (challenge.e * (sigma_p.r_3 - (sigma_p.r_1 * sigma_p.m_2)));

    Response{
        z_1, z_2, z_3, z_4, z_5
    }
}

/// (4) The verifier checks each Pederesen commitment to finish the protocol.
pub fn verify(pp: &pedersen::PublicParams, sigma_v: &mut Verifier, response: &Response) -> bool {

    let special_pp = pedersen::PublicParams {
        g: sigma_v.c_1,
        h: pp.h,
    };

    if !pedersen::verify(&sigma_v.c1_prime, &response.z_1, &response.z_2, pp) {
        return false;
    }

    if !pedersen::verify(&sigma_v.c2_prime, &response.z_3, &response.z_4, pp) {
        return false;
    }

    if !pedersen::verify(&sigma_v.c3_prime, &response.z_3, &response.z_5, &special_pp) {
        return false;
    }

    return true
}
