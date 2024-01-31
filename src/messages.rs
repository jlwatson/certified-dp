use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Serialize, Deserialize, Debug)]
pub struct SetupMessage {
    pub seed: [u8; 32]
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CommitmentMapMessage<T: Eq + Hash> {
    pub commitment_map: HashMap<T, RistrettoPoint>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProverRandomnessComm {
    pub dealer_b_comm: RistrettoPoint,
    pub c0: RistrettoPoint,
    pub c1: RistrettoPoint
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifierRandomnessChallenge {
    pub player_b: u32,
    pub player_e: Scalar
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ProverRandomnessResponse {
    pub final_commitment: RistrettoPoint,
    pub z0: Scalar,
    pub z1: Scalar,
    pub e0: Scalar,
    pub e1: Scalar
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerifierRandomnessResult {
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