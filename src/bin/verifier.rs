use clap::Parser;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use rand::{Rng, SeedableRng};
use rand::prelude::IteratorRandom;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::io::{self, Write};
use std::mem::size_of;
use std::net::{SocketAddr, TcpStream};
use std::ops::Neg;
use std::time::Duration;
use std::time::Instant;

use vdp_poc::config::get_n;
use vdp_poc::messages::{read_from_stream, write_to_stream, CommitmentMapMessage, ProverRandomnessComm, ProverRandomnessResponse, VerifierRandomnessResult, QueryAnswerMessage, QueryMessage, SetupMessage, VerifierRandomnessChallenge};
use vdp_poc::pedersen::{setup, commit_with_r, verify, PublicParams};

#[allow(non_snake_case, dead_code)]
struct VerifierState<T> {
    rng: OsRng,
    shared_rng: ChaCha20Rng,
    pedersen_pp: PublicParams,
    monomial_commitments: HashMap<T, RistrettoPoint>,
    player_b: u32,
    player_e: Scalar,
    randomness_bit_comm: RistrettoPoint,

    C0: RistrettoPoint,
    C1: RistrettoPoint,
    CPROOF: Scalar,
}

//
// -- SETUP PHASE --
//

// 1
fn verifier_setup<T>(stream: &mut TcpStream) -> VerifierState<T> {

    let rng = OsRng::default();
   
    let setup_message: SetupMessage = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    let mut shared_rng = ChaCha20Rng::from_seed(setup_message.seed);

    let pp= setup(&mut shared_rng);

    let proof_val = Scalar::from(0 as u32);
    VerifierState {
        rng: rng,
        shared_rng: shared_rng,
        pedersen_pp: pp.clone(),
        monomial_commitments: HashMap::new(),
        C0: commit_with_r(&Scalar::from(0 as u32), &proof_val, &pp),
        C1: commit_with_r(&Scalar::from(1 as u32), &proof_val, &pp),
        CPROOF: proof_val,
        player_b: 0,
        player_e: Scalar::default(),
        randomness_bit_comm: RistrettoPoint::default(),
    }
}

//
// -- COMMITMENT PHASE --
//

// 3
fn verifier_commitment_phase<T>(state: &mut VerifierState<T>, stream: &mut TcpStream)
where T: Eq + Hash + DeserializeOwned
{
    
    let m: CommitmentMapMessage<T> = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    state.monomial_commitments = m.commitment_map;
}

//
// -- RANDOMNESS PHASE --
//

// 5
fn verifer_randomness_phase_challenge<T>(state: &mut VerifierState<T>, stream: &mut TcpStream) {

    // CF 2: PL flips a bit and sends it
    let player_b: u32 = state.rng.gen_range(0..2);

    // SP 2: PL sends a random e value
    let player_e = Scalar::random(&mut state.rng);

    let m: VerifierRandomnessChallenge = VerifierRandomnessChallenge {
        player_b: player_b,
        player_e: player_e
    };
    write_to_stream(
        stream, serde_json::to_string(&m).unwrap()
    );

    state.player_b = player_b;
    state.player_e = player_e;
}

// 7
fn verifier_randomness_phase_check<T>(state: &mut VerifierState<T>, stream: &mut TcpStream) -> Option<RistrettoPoint> {

    let comm_msg: ProverRandomnessComm = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    let resp_msg: ProverRandomnessResponse = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    // CF 4
    if state.player_b == 0 {
        if resp_msg.final_commitment != comm_msg.dealer_b_comm {
            println!("ERROR: player_b = 0, final_commitment != dealer_b_comm");
            write_to_stream(
                stream, serde_json::to_string(&VerifierRandomnessResult {success: false}).unwrap()
            );
            return None;
        }
    } else {
        if resp_msg.final_commitment != state.C1 + comm_msg.dealer_b_comm.neg() {
            println!("ERROR: player_b = 1, final_commitment != C1 + dealer_b_comm.neg()");
            write_to_stream(
                stream, serde_json::to_string(&VerifierRandomnessResult {success: false}).unwrap()
            );
            return None;
        }
    }

    // SP 4
    if state.player_e != resp_msg.e0 + resp_msg.e1 {
        println!("ERROR: player_e != e0 + e1");
        write_to_stream(
            stream, serde_json::to_string(&VerifierRandomnessResult {success: false}).unwrap()
        );
        return None;
    }

    let comm_0 = commit_with_r(&Scalar::from(0 as u32), &resp_msg.z0, &state.pedersen_pp);
    if comm_0 != comm_msg.c0 + (resp_msg.e0 * comm_msg.dealer_b_comm) {
        println!("ERROR: comm_0 != c0 + (e0 * dealer_b_comm)");
        write_to_stream(
            stream, serde_json::to_string(&VerifierRandomnessResult {success: false}).unwrap()
        );
        return None;
    }

    let comm_1 = commit_with_r(&(Scalar::from(1 as u32) + resp_msg.e1), &resp_msg.z1, &state.pedersen_pp);
    if comm_1 != comm_msg.c1 + (resp_msg.e1 * comm_msg.dealer_b_comm){
        println!("ERROR: comm_1 != c1 + (e1 * dealer_b_comm)");
        write_to_stream(
            stream, serde_json::to_string(&VerifierRandomnessResult {success: false}).unwrap()
        );
        return None;
    }

    write_to_stream(
        stream, serde_json::to_string(&VerifierRandomnessResult {success: true}).unwrap()
    );
    return Some(resp_msg.final_commitment);
}

// 9
fn verifier_randomness_phase_adjust<T>(state: &mut VerifierState<T>, db_size: u32, epsilon: f32) {
    let adjustment_factor = Scalar::from((get_n(db_size, epsilon)/2) as u32);
    state.randomness_bit_comm -= commit_with_r(&adjustment_factor, &state.CPROOF, &state.pedersen_pp);
}

//
// -- QUERYING PHASE --
//

// 10
fn verifier_generate_query<T: Eq + Hash + Copy>(state: &mut VerifierState<T>, sparsity: u32) -> HashMap<T, Scalar> {

    let mut coefficients: HashMap<T, Scalar> = HashMap::new();
    // this NUM_COEFF controls the polynomial sparsity
    for _ in 0..sparsity {
        let mut random_id = state.monomial_commitments.keys().choose(&mut state.rng).unwrap();
        while coefficients.contains_key(random_id) {
            random_id = state.monomial_commitments.keys().choose(&mut state.rng).unwrap();
        }
        let coeff = Scalar::random(&mut state.rng);
        coefficients.insert(*random_id, coeff);
    }

    coefficients
}

// 11
fn verifier_send_query<T>(_state: &mut VerifierState<T>, stream: &mut TcpStream, query_coefficients: &HashMap<T, Scalar>)
where T: Eq + Hash + Clone + Serialize
{
    let m = QueryMessage::<T> {
        coefficients: query_coefficients.clone()
    };
    write_to_stream(
        stream, serde_json::to_string(&m).unwrap()
    );
}

// 13
fn verifier_check_query<T>(state: &mut VerifierState<T>, stream: &mut TcpStream, query_coefficients: &HashMap<T, Scalar>)
where T: Eq + Hash + Display
{
    let query_answer_m: QueryAnswerMessage = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    let mut query_comm = state.randomness_bit_comm;

    // measure homomorphic operations
    for monomial_id in query_coefficients.keys() {
        if !state.monomial_commitments.contains_key(monomial_id) {
            println!("ERROR: Monomial ID {} not found in monomial commitment map", monomial_id);
            return;
        }

        let monomial_comm = state.monomial_commitments.get(monomial_id).unwrap();
        let monomial_coefficient = query_coefficients.get(monomial_id).unwrap();

        query_comm += monomial_coefficient * monomial_comm;
    }

    let query_answer = query_answer_m.answer;
    let query_proof = query_answer_m.proof;

    // measure verification check
    if verify(&query_comm, &query_proof, &query_answer, &state.pedersen_pp) {
        println!("verified!");
    } else {
        println!("INVALID :(");
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // number of elements in the database
    #[arg(long)]
    db_size: u32,

    // max monomial degree
    #[arg(long)]
    max_degree: u32,

    // differential privacy epsilon
    #[arg(long)]
    epsilon: f32,

    // sparsity -- aka max coefficients in query polynomial
    #[arg(long)]
    sparsity: u32,

    // prover address
    #[arg(long)]
    prover_address: String,
}

fn main() {

    type DataT = u32;

    println!("\n-- Running VDP Verifier --\n");

    let args = Args::parse();
    println!("Configuration:");
    println!("\tDatabase size: {}", args.db_size);
    println!("\tDimension: {}", size_of::<DataT>());
    println!("\tMax degree: {}", args.max_degree);
    println!("\tEpsilon: {}", args.epsilon);
    println!("\tSparsity: {}", args.sparsity);
    println!("\tProver address: {}", args.prover_address);
    println!("");

    // Setup
    print!("Setup phase...");
    io::stdout().flush().unwrap();

    let addr = args.prover_address.parse::<SocketAddr>().unwrap();
    let mut stream = TcpStream::connect_timeout(
        &addr,
        Duration::from_secs(10)
    ).unwrap();

    let mut verifier_state = verifier_setup::<DataT>(&mut stream);
    
    println!("complete");

    // Commitment Phase
    print!("Commitment phase...");
    io::stdout().flush().unwrap();
   
    let start_comm = Instant::now();
    verifier_commitment_phase(&mut verifier_state, &mut stream);
    let duration_comm = start_comm.elapsed();
   
    println!("complete");
    println!("  COMMITMENT duration: {:?}", duration_comm);
    
    // Randomness Phase
    print!("Randomness phase...");
    io::stdout().flush().unwrap();

    let start_rnd = Instant::now();
    verifier_state.randomness_bit_comm = verifier_state.C0;

    for _ in 0..get_n(args.db_size, args.epsilon) {
        verifer_randomness_phase_challenge(&mut verifier_state, &mut stream);
        match verifier_randomness_phase_check(&mut verifier_state, &mut stream) {
            Some(c) => {
                verifier_state.randomness_bit_comm += c;
            },
            None => {
                println!("ERROR: Randomness phase failed");
                return;
            }
        }
    }
    verifier_randomness_phase_adjust(&mut verifier_state, args.db_size, args.epsilon);
    let duration_rnd = start_rnd.elapsed();

    println!("complete");
    println!("  RANDOMNESS GEN duration: {:?}", duration_rnd);

    // Query generation
    print!("Query generation...");
    io::stdout().flush().unwrap();

    let query_coefficients = verifier_generate_query(&mut verifier_state, args.sparsity);
    
    println!("complete");

    // Query phase
    print!("Query phase...");
    io::stdout().flush().unwrap();

    let start_query = Instant::now();
    verifier_send_query(&mut verifier_state, &mut stream, &query_coefficients);
    verifier_check_query(&mut verifier_state, &mut stream, &query_coefficients);
    let duration_query = start_query.elapsed();
    println!("  QUERY duration: {:?}", duration_query);
    
    println!("");
}