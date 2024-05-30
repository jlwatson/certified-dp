/**
 * messages.rs
 * 
 * Structures for all messages sent over the network during the protocol execution between the prover and verifier.
 */

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hash;
use std::io::{Read, Write};
use std::net::TcpStream;

use crate::bit_sigma;
use crate::product_sigma;

/// Message to synchronize the start of the protocol
#[derive(Serialize, Deserialize, Debug)]
pub struct ReadyMessage {
    pub ready: bool
}

/// Seed for shared randomness generation
#[derive(Serialize, Deserialize, Debug)]
pub struct SetupMessage {
    pub seed: [u8; 32]
}

/// Set of commitments for bits in the database entries
#[derive(Serialize, Deserialize, Debug)]
pub struct BitSigmaCommitmentMessage {
    pub commitments: Vec<bit_sigma::Commitment>,
}

/// Tree of product sigma commitments for the database entries
#[derive(Serialize, Deserialize, Debug)]
pub struct MonomialCommitmentTreeNode {
    pub commitment: Option<RistrettoPoint>,
    pub product_sigma_commitment: Option<product_sigma::Commitment>,
    pub children: Vec<Box<MonomialCommitmentTreeNode>>,
}

/// Set of challenges for bits in the database entries
#[derive(Serialize, Deserialize, Debug)]
pub struct BitSigmaChallengeMessage {
    pub challenges: Vec<bit_sigma::Challenge>,
}

/// Tree of product sigma challenges for the database entries, mirror to the commitment tree
#[derive(Serialize, Deserialize, Debug)]
pub struct MonomialChallengeTreeNode {
    pub product_sigma_challenge: Option<product_sigma::Challenge>,
    pub children: Vec<Box<MonomialChallengeTreeNode>>,
}

/// Set of responses for bits in the database entries
#[derive(Serialize, Deserialize, Debug)]
pub struct BitSigmaResponseMessage {
    pub responses: Vec<bit_sigma::Response>,
}

/// Tree of product sigma responses for the database entries, mirror to the commitment and challenge trees
#[derive(Serialize, Deserialize, Debug)]
pub struct MonomialResponseTreeNode {
    pub product_sigma_response: Option<product_sigma::Response>,
    pub children: Vec<Box<MonomialResponseTreeNode>>,
}

/// Contains the final monomial commitments for the database entries
#[derive(Serialize, Deserialize, Debug)]
pub struct CommitmentMapMessage<T: Eq + Hash> {
    pub commitment_map: HashMap<T, RistrettoPoint>
}

/// Prover randomness phase commitment
#[derive(Serialize, Deserialize, Debug)]
pub struct ProverRandomnessComm {
    pub commitment: bit_sigma::Commitment,
}

/// Verifier randomness phase challenge
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifierRandomnessChallenge {
    pub player_b: u32,
    pub sigma_challenge: bit_sigma::Challenge
}

/// Prover randomness phase response
#[derive(Serialize, Deserialize, Debug)]
pub struct ProverRandomnessResponse {
    pub final_commitment: RistrettoPoint,
    pub sigma_response: bit_sigma::Response
}

/// Verifier randomness phase check; indicator of success
#[derive(Serialize, Deserialize, Debug)]
pub struct VerifierCheckMessage {
    pub success: bool
}

/// Verifier specific query
#[derive(Serialize, Deserialize, Debug)]
pub struct QueryMessage<T: Eq + Hash> {
    pub coefficients: HashMap<T, Scalar>
}

/// Prover answer to a verifier query
#[derive(Serialize, Deserialize, Debug)]
pub struct QueryAnswerMessage {
    pub answer: Scalar,
    pub proof: Scalar
}

/// Reads a buffer of bytes from a stream, determined by a 4-byte size header
pub fn read_from_stream(stream: &mut TcpStream) -> Vec<u8> {

    let mut size_buf = [0; 4];
    stream.read_exact(&mut size_buf).unwrap();

    let size = u32::from_le_bytes(size_buf) as usize;
    let mut buffer = vec![0; size];
    stream.read_exact(&mut buffer).unwrap();

    buffer
}

/// Writes a buffer of bytes to a stream, with a 4-byte size header
pub fn write_to_stream(stream: &mut TcpStream, a: &[u8]) {
    let size_buf = (a.len() as u32).to_le_bytes();
    match stream.write_all(&size_buf) {
        Ok(_) => (),
        Err(e) => println!("Error: {}", e)
    }

    match stream.write(&a) {
        Ok(_) => (),
        Err(e) => println!("Error: {}", e)
    }
}

/// Compresses a buffer of bytes using gzip, trades off speed for compression ratio
pub fn compress(buf: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(buf).unwrap();
    encoder.finish().unwrap().to_vec()
}

/// Decompresses a buffer of bytes using gzip
pub fn decompress(buf: &[u8]) -> Vec<u8> {
    let mut decoder = GzDecoder::new(buf);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).unwrap();
    decompressed
}