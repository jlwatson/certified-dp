use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::io::{Read, Write};
use std::net::TcpStream;

use crate::bit_sigma;
use crate::product_sigma;

#[derive(Serialize, Deserialize, Debug)]
pub struct ReadyMessage {
    pub ready: bool
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SetupMessage {
    pub seed: [u8; 32]
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BitSigmaCommitmentMessage {
    pub commitments: Vec<bit_sigma::Commitment>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MonomialCommitmentTreeNode {
    pub commitment: Option<RistrettoPoint>,
    pub product_sigma_commitment: Option<product_sigma::Commitment>,
    pub children: Vec<Box<MonomialCommitmentTreeNode>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BitSigmaChallengeMessage {
    pub challenges: Vec<bit_sigma::Challenge>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MonomialChallengeTreeNode {
    pub product_sigma_challenge: Option<product_sigma::Challenge>,
    pub children: Vec<Box<MonomialChallengeTreeNode>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BitSigmaResponseMessage {
    pub responses: Vec<bit_sigma::Response>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MonomialResponseTreeNode {
    pub product_sigma_response: Option<product_sigma::Response>,
    pub children: Vec<Box<MonomialResponseTreeNode>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CommitmentMapMessage<T: Eq + Hash> {
    pub commitment_map: HashMap<T, RistrettoPoint>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProverRandomnessComm {
    pub commitment: bit_sigma::Commitment,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifierRandomnessChallenge {
    pub player_b: u32,
    pub sigma_challenge: bit_sigma::Challenge
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProverRandomnessResponse {
    pub final_commitment: RistrettoPoint,
    pub sigma_response: bit_sigma::Response
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifierCheckMessage {
    pub success: bool
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryMessage<T: Eq + Hash> {
    pub coefficients: HashMap<T, Scalar>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct QueryAnswerMessage {
    pub answer: Scalar,
    pub proof: Scalar
}

pub fn read_from_stream(stream: &mut TcpStream) -> String {

    let mut size_buf = [0; 4];
    stream.read_exact(&mut size_buf).unwrap();

    let size = u32::from_le_bytes(size_buf) as usize;
    let mut buffer = vec![0; size];
    stream.read_exact(&mut buffer).unwrap();
    String::from_utf8_lossy(&buffer[..]).to_string()
}

pub fn write_to_stream(stream: &mut TcpStream, a: String) {

    let size_buf = (a.len() as u32).to_le_bytes();
    match stream.write_all(&size_buf) {
        Ok(_) => (),
        Err(e) => println!("Error: {}", e)
    }

    match stream.write(a.as_bytes()) {
        Ok(_) => (),
        Err(e) => println!("Error: {}", e)
    }
}