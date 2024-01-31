use clap::Parser;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use num_traits::PrimInt;
use rand::{Rng, SeedableRng};
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::mem::size_of;
use std::io::{self, Write};
use std::net::{TcpStream, TcpListener};
use std::ops::Neg;
use std::time::Instant;

use vdp_poc::config::{get_n, PROVER_ADDRESS, PROVER_PORT};
use vdp_poc::data::Data;
use vdp_poc::messages::{write_to_stream, read_from_stream, SetupMessage, CommitmentMapMessage, ProverRandomnessComm, VerifierRandomnessChallenge, ProverRandomnessResponse, VerifierRandomnessResult, QueryMessage, QueryAnswerMessage};
use vdp_poc::pedersen::{setup, commit, commit_with_r, PublicParams};

#[allow(non_snake_case, dead_code)]
struct ProverState<T> {
    rng: OsRng,
    shared_rng: ChaCha20Rng,
    pedersen_pp: PublicParams,
    monomial_map: HashMap<T, (Scalar, RistrettoPoint, Scalar)>,
    dealer_b: u32,
    dealer_b_comm: RistrettoPoint,
    dealer_b_proof: Scalar,
    dealer_e: Scalar,
    dealer_sigma_b_comm: RistrettoPoint,
    dealer_sigma_b_proof: Scalar,
    dealer_sigma_not_b_proof: Scalar,
    final_b: u32,
    final_proof: Scalar,
    randomness_bit_sum: Scalar,
    randomness_bit_proof: Scalar,

    C0: RistrettoPoint,
    C1: RistrettoPoint,
    CPROOF: Scalar,
}

//
// -- SETUP PHASE --
//

// 0
fn prover_setup<T>(stream: &mut TcpStream) -> ProverState<T> {

    let mut rng = OsRng::default();
    let prover_seed = rng.gen::<[u8; 32]>();

    let mut shared_rng = ChaCha20Rng::from_seed(prover_seed);

    let pp = setup(&mut shared_rng);

    let proof_val = Scalar::from(0 as u32);

    let setup_message = SetupMessage {
        seed: prover_seed
    };
    write_to_stream(
        stream, serde_json::to_string(&setup_message).unwrap()
    );

    ProverState {
        rng: rng,
        shared_rng: shared_rng,
        pedersen_pp: pp.clone(),
        monomial_map: HashMap::new(),
        C0: commit_with_r(&Scalar::from(0 as u32), &proof_val, &pp),
        C1: commit_with_r(&Scalar::from(1 as u32), &proof_val, &pp),
        CPROOF: proof_val,
        dealer_b: 0,
        dealer_b_comm: RistrettoPoint::default(),
        dealer_b_proof: Scalar::default(),
        dealer_e: Scalar::default(),
        dealer_sigma_b_comm: RistrettoPoint::default(),
        dealer_sigma_b_proof: Scalar::default(),
        dealer_sigma_not_b_proof: Scalar::default(),
        final_b: 0,
        final_proof: Scalar::default(),
        randomness_bit_sum: Scalar::default(),
        randomness_bit_proof: Scalar::default(),
    }
}

//
// -- COMMITMENT PHASE --
//

fn calculate_monomial_sum<T: PrimInt>(indices: T, data: &[T]) -> Scalar {

    let mut sum = Scalar::from(0 as u8);
    for i in 0..data.len() {
        let monomial: u8 = if (data[i] & indices).count_zeros() > 0 { 0 } else { 1 };
        sum += Scalar::from(monomial);
    }

    sum
}

fn generate_monomial_sums_helper<T: PrimInt + Hash>(indices: T, current_idx: T, data: &[T], monomial_map: &mut HashMap<T, Scalar>,
                                                    dimension: u32, max_degree: u32) {

    if current_idx.to_u32().unwrap() == dimension || indices.count_ones() == max_degree {
        let sum = calculate_monomial_sum(indices, data);
        monomial_map.insert(indices, sum);
        return;
    }

    // set bit at current index to a 0 or 1 and recurse
    generate_monomial_sums_helper(
        indices, current_idx + T::one(), data, monomial_map, dimension, max_degree);
    generate_monomial_sums_helper(
        indices | (T::one() << current_idx.to_usize().unwrap()), current_idx + T::one(), data, monomial_map, dimension, max_degree);
}

fn generate_monomial_sums<T: PrimInt + Hash>(data: &[T], dimension: u32, max_degree: u32) -> HashMap<T, Scalar> {
    let mut map = HashMap::new();
    generate_monomial_sums_helper(T::zero(), T::zero(), data, &mut map, dimension, max_degree);
    map
}

// 2
fn prover_commitment_phase<T: PrimInt + Hash + Serialize>(state: &mut ProverState<T>, stream: &mut TcpStream, database: &mut Data<T>, dimension: u32, max_degree: u32) {

    let monomial_map = generate_monomial_sums(&database.entries, dimension, max_degree);

    let mut monomial_commitments = HashMap::new();
    for (monomial_id, monomial_sum) in monomial_map {
        let (comm, proof) = commit(&mut state.rng, &monomial_sum, &state.pedersen_pp);
        state.monomial_map.insert(monomial_id, (monomial_sum, comm, proof));
        monomial_commitments.insert(monomial_id, comm);
    } 

    let m = CommitmentMapMessage::<T> {
        commitment_map: monomial_commitments
    };

    write_to_stream(
        stream, serde_json::to_string(&m).unwrap()
    );

    database.commitments = state.monomial_map.clone();
}

//
// -- RANDOMNESS PHASE --
//

// 4
fn prover_randomness_phase_comm<T>(state: &mut ProverState<T>, stream: &mut TcpStream) {

    // CF 1: DE flips random bit and commits to i
    let dealer_b: u32 = state.rng.gen_range(0..2);
    let (dealer_b_comm, dealer_b_proof ) =
        commit(&mut state.rng, &Scalar::from(dealer_b), &state.pedersen_pp); 

    // SP 1: DE commits to the same bit with fresh randomness. DE randomly selects an e.
    //       DE commits to the opposite bit and scales the original commitment 
    let (dealer_sigma_b_comm, dealer_sigma_b_proof) = 
        commit(&mut state.rng, &Scalar::from(dealer_b), &state.pedersen_pp);

    let dealer_e = Scalar::random(&mut state.rng);
    let (dealer_sigma_not_b_comm, dealer_sigma_not_b_proof) = 
        commit(&mut state.rng, &(Scalar::from(1 - dealer_b) * (dealer_e + Scalar::from(1 as u32))), &state.pedersen_pp);

    //let dealer_sigma_fake_comm = add_comm(&dealer_sigma_not_b_comm, &scale_comm(&dealer_b_comm, &dealer_e.negate()));
    let dealer_sigma_fake_comm = dealer_sigma_not_b_comm + (dealer_e.neg() * dealer_b_comm);

    let c0 = if dealer_b == 0 { dealer_sigma_b_comm } else { dealer_sigma_fake_comm };
    let c1 = if dealer_b == 1 { dealer_sigma_b_comm } else { dealer_sigma_fake_comm };

    let m: ProverRandomnessComm = ProverRandomnessComm {
        dealer_b_comm: dealer_b_comm,
        c0: c0,
        c1: c1
    };
    write_to_stream(
        stream, serde_json::to_string(&m).unwrap()
    );

    state.dealer_b = dealer_b;
    state.dealer_b_comm = dealer_b_comm;
    state.dealer_b_proof = dealer_b_proof;
    state.dealer_e = dealer_e;
    state.dealer_sigma_b_comm = dealer_sigma_b_comm;
    state.dealer_sigma_b_proof = dealer_sigma_b_proof;
    state.dealer_sigma_not_b_proof = dealer_sigma_not_b_proof;
}

// 6
fn prover_randomness_phase_response<T>(state: &mut ProverState<T>, stream: &mut TcpStream) -> bool {

    // CF 3
    let final_commitment: RistrettoPoint;
    let final_proof: Scalar;
    let final_b: u32;

    let m: VerifierRandomnessChallenge = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    if m.player_b == 0 {
        final_commitment = state.dealer_b_comm;
        final_proof = state.dealer_b_proof;
        final_b = state.dealer_b;
    } else { // player_b == 1
        final_commitment = state.C1 + state.dealer_b_comm.neg();
        final_proof = state.CPROOF + state.dealer_b_proof.neg();

        final_b = 1 - state.dealer_b;
    }

    // SP 3
    let dealer_new_e = m.player_e - state.dealer_e;

    let z = state.dealer_sigma_b_proof + (dealer_new_e * state.dealer_b_proof);

    let z0 = if state.dealer_b == 0 { z } else { state.dealer_sigma_not_b_proof };
    let z1 = if state.dealer_b == 1 { z } else { state.dealer_sigma_not_b_proof };

    let e0 = if state.dealer_b == 0 { dealer_new_e } else { state.dealer_e };
    let e1 = if state.dealer_b == 1 { dealer_new_e } else { state.dealer_e };

    let m: ProverRandomnessResponse = ProverRandomnessResponse {
        final_commitment: final_commitment,
        z0: z0,
        z1: z1,
        e0: e0,
        e1: e1
    };
    write_to_stream(
        stream, serde_json::to_string(&m).unwrap()
    );

    state.final_b = final_b;
    state.final_proof = final_proof;

    let result: VerifierRandomnessResult = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    result.success
}

// 8
fn prover_randomness_phase_adjust<T>(state: &mut ProverState<T>, db_size: u32, epsilon: f32) {
    let adjustment_factor = Scalar::from((get_n(db_size, epsilon)/2) as u32);
    state.randomness_bit_sum -= adjustment_factor;
    state.randomness_bit_proof -= state.CPROOF;
}

//
// -- QUERYING PHASE --
//

//12
fn prover_answer_query<T>(state: &mut ProverState<T>, stream: &mut TcpStream)
where T: Eq + Hash + Display + DeserializeOwned
{
    let query_m: QueryMessage<T> = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    let mut query_answer = state.randomness_bit_sum;
    let mut query_proof = state.randomness_bit_proof;

    for monomial_id in query_m.coefficients.keys() {
        if !state.monomial_map.contains_key(monomial_id) {
            println!("ERROR: Monomial ID {} not found in monomial map", monomial_id);
            return;
        }

        let (monomial_sum, _monomial_comm, monomial_proof) = state.monomial_map.get(monomial_id).unwrap();
        let monomial_coefficient = query_m.coefficients.get(monomial_id).unwrap();

        query_answer += monomial_coefficient * monomial_sum;
        query_proof += monomial_coefficient * monomial_proof;
    }

    write_to_stream(
        stream,
        serde_json::to_string(&QueryAnswerMessage {
            answer: query_answer,
            proof: query_proof
        }).unwrap()
    );
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

    // path to database file(s)
    #[arg(long)]
    db_path: String,
}

fn main() {

    type DataT = u32;

    // database size
    // size of the database entries = max monomial degree
        // 8, 16, 32, 64
    // epsilon
    // (verifier) sparsity aka num_coeff
    // (verifier)  prover ip and port

    // TIMING STUFF
    // mainly phases, but the verification split up as commented
    // save commitment information and run rng/query phase multiple times


    println!("\n-- Running VDP Prover --\n");

    let args = Args::parse();
    println!("Configuration:");
    println!("\tDatabase size: {}", args.db_size);
    println!("\tDimension: {}", size_of::<DataT>());
    println!("\tMax degree: {}", args.max_degree);
    println!("\tEpsilon: {}", args.epsilon);
    println!("\tDatabase path: {}", args.db_path);
    println!("");

    // Setup
    print!("Setup phase...");
    io::stdout().flush().unwrap();

    let listener = TcpListener::bind(format!("{}:{}", PROVER_ADDRESS, PROVER_PORT)).unwrap();
    let (mut stream, _) = listener.accept().unwrap();

    let mut prover_state = prover_setup::<DataT>(&mut stream);

    let mut database = Data::new(&mut prover_state.rng, args.db_size);

    println!("complete");

    // Commitment Phase
    print!("Commitment phase...");
    io::stdout().flush().unwrap();
   
    let start_comm = Instant::now();
    prover_commitment_phase(&mut prover_state, &mut stream, &mut database, size_of::<DataT>() as u32, args.max_degree);
    let duration_comm = start_comm.elapsed();
   
    println!("complete");
    println!("  COMMITMENT phase duration: {:?}", duration_comm);
    println!("    per-monomial: {:?} ({:?} monomials)", duration_comm / prover_state.monomial_map.len() as u32, prover_state.monomial_map.len());
    
    // Randomness Phase
    print!("Randomness phase...");
    io::stdout().flush().unwrap();

    let start_rnd = Instant::now();
    prover_state.randomness_bit_sum = Scalar::from(0 as u32);
    prover_state.randomness_bit_proof = prover_state.CPROOF;

    for _ in 0..get_n(args.db_size, args.epsilon) {
        prover_randomness_phase_comm(&mut prover_state, &mut stream);
        if prover_randomness_phase_response(&mut prover_state, &mut stream) {
            prover_state.randomness_bit_sum += Scalar::from(prover_state.final_b);
            prover_state.randomness_bit_proof += prover_state.final_proof;
        } else {
            println!("ERROR: Randomness phase failed");
            return;
        }
    }
    prover_randomness_phase_adjust(&mut prover_state, args.db_size, args.epsilon);
    let duration_rnd = start_rnd.elapsed();

    println!("complete");
    println!("  RANDOMNESS GEN phase duration: {:?}", duration_rnd);
    println!("    per-iteration: {:?} (N = {} iterations)", duration_rnd / get_n(args.db_size, args.epsilon), get_n(args.db_size, args.epsilon));

    // Query phase
    print!("Query phase...");
    io::stdout().flush().unwrap();

    let start_query = Instant::now();
    prover_answer_query(&mut prover_state, &mut stream);
    let duration_query = start_query.elapsed();

    println!("complete");
    println!("  QUERY phase duration: {:?}", duration_query);

    println!("");
}
