/**
 * verifier.rs
 * 
 * Primary Verifier executable with the following arguments:
 *   
 *   db_size: number of elements in the database
 *   epsilon: differential privacy epsilon
 *   delta: (optional) differential privacy delta, otherwise calculated based on the database size
 *   sparsity: max coefficients in query polynomial
 *   prover_address: prover url and port for communication
 *   dimension: (optional) dimension (bitsize) of the database entries
 *   skip_dishonest: (optional) skip dishonest commitment phase if desired
 *   num_queries: (optional) number of queries to execute and average runtime over
 *   sparsity_experiment: (optional) sspecial flag to evaluate sparsity experiment
 */

#[macro_use] extern crate prettytable;

use clap::Parser;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use itertools::Itertools;
use num_traits::{pow, PrimInt};
use rand::{Rng, SeedableRng};
use rand::prelude::IteratorRandom;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::mem::size_of;
use std::net::{SocketAddr, TcpStream};
use std::ops::Neg;
use std::time::Duration;
use std::time::Instant;

use certified_dp::bit_sigma;
use certified_dp::product_sigma;
use certified_dp::config::{get_n, get_delta, DataT};
use certified_dp::messages::{read_from_stream, write_to_stream, BitSigmaChallengeMessage, BitSigmaCommitmentMessage, BitSigmaResponseMessage, CommitmentMapMessage, MonomialChallengeTreeNode, MonomialCommitmentTreeNode, MonomialResponseTreeNode, ProverRandomnessComm, ProverRandomnessResponse, QueryAnswerMessage, QueryMessage, ReadyMessage, SetupMessage, VerifierCheckMessage, VerifierRandomnessChallenge};
use certified_dp::pedersen;

/// Verifier state for the main protocol.
#[allow(non_snake_case)]
struct VerifierState<T>
where T: PrimInt + Hash
{
    rng: OsRng,
    pedersen_pp: pedersen::PublicParams,
    monomial_commitments: HashMap<T, RistrettoPoint>,
    player_b: u32,
    randomness_bit_comm: RistrettoPoint,
    sigma_verifier: bit_sigma::Verifier,

    C0: RistrettoPoint,
    C1: RistrettoPoint,
    CPROOF: Scalar,

    comm_verify_duration: Duration,
    randomness_bit_sigma_verify_duration: Duration,
    randomness_coin_flip_agg_duration: Duration,
}

///
/// -- SETUP PHASE --
///

/// Setup the verifier with the shared randomness seed from the prover and initialize state.
fn verifier_setup<T: PrimInt + Hash>(stream: &mut TcpStream) -> VerifierState<T> {

    let rng = OsRng::default();
   
    let setup_message: SetupMessage = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();

    let mut shared_rng = ChaCha20Rng::from_seed(setup_message.seed);
    let pp= pedersen::setup(&mut shared_rng);

    let proof_val = Scalar::from(0 as u32);
    VerifierState {
        rng,
        pedersen_pp: pp.clone(),
        monomial_commitments: HashMap::new(),
        C0: pedersen::commit_with_r(&Scalar::from(0 as u32), &proof_val, &pp),
        C1: pedersen::commit_with_r(&Scalar::from(1 as u32), &proof_val, &pp),
        CPROOF: proof_val,
        player_b: 0,
        randomness_bit_comm: RistrettoPoint::default(),
        sigma_verifier: bit_sigma::Verifier::default(),

        randomness_bit_sigma_verify_duration: Duration::from_secs(0),
        randomness_coin_flip_agg_duration: Duration::from_secs(0),
        comm_verify_duration: Duration::from_secs(0),
    }
}

///
/// -- COMMITMENT PHASE --
///

/// Honest commitment phase: read commitment map from prover.
fn verifier_honest_commitment_phase<T: PrimInt + Hash>(state: &mut VerifierState<T>, stream: &mut TcpStream)
where T: Eq + Hash + DeserializeOwned
{
    let m: CommitmentMapMessage<T> = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();

    state.monomial_commitments = m.commitment_map;
}

/// Tree-based structure of product sigma protocols to verify commitments to database entries.
pub struct MonomialVerifierTreeNode {
    pub commitment: Option<RistrettoPoint>,
    pub product_sigma_verifier: Option<product_sigma::Verifier>,
    pub children: Vec<Box<MonomialVerifierTreeNode>>,
}

/// Based on a tree of product sigma commitment nodes, generate a matching tree of challenges to send to the prover.
fn gen_challenge_tree<T: PrimInt + Hash>(state: &mut VerifierState<T>, curr_comm_node: &MonomialCommitmentTreeNode, curr_verifier_node: &mut MonomialVerifierTreeNode, curr_challenge_node: &mut MonomialChallengeTreeNode) {
    if let Some(comm) = &curr_comm_node.commitment {
        curr_verifier_node.commitment = Some(comm.clone());
    }

    if let Some(sigma_comm) = &curr_comm_node.product_sigma_commitment {
        let (sigma_verifier, sigma_challenge) = product_sigma::challenge(&mut state.rng, &sigma_comm);
        curr_verifier_node.product_sigma_verifier = Some(sigma_verifier);
        curr_challenge_node.product_sigma_challenge = Some(sigma_challenge);
    }

    for child in &curr_comm_node.children {
        let mut child_verifier = MonomialVerifierTreeNode {
            commitment: None,
            product_sigma_verifier: None,
            children: Vec::new(),
        };
        let mut child_challenge = MonomialChallengeTreeNode {
            product_sigma_challenge: None,
            children: Vec::new(),
        };
        gen_challenge_tree(state, child, &mut child_verifier, &mut child_challenge);
        curr_verifier_node.children.push(Box::new(child_verifier));
        curr_challenge_node.children.push(Box::new(child_challenge));
    }
}

/// Recursively verify the response tree of sigma protocol nodes generated by the prover.
fn verify_response_tree(state: &pedersen::PublicParams, curr_verifier_node: &mut MonomialVerifierTreeNode, curr_response_node: &MonomialResponseTreeNode) -> bool {

    let mut sigma_verified = true;

    if let Some(sigma_verifier) = &mut curr_verifier_node.product_sigma_verifier {
        sigma_verified = product_sigma::verify(state, sigma_verifier, curr_response_node.product_sigma_response.as_ref().unwrap());
        if !sigma_verified {
            eprintln!("ERROR: Product sigma verification failed");
        }
    }

    for (i, child) in curr_verifier_node.children.iter_mut().enumerate() {
        sigma_verified &= verify_response_tree(state, child, &curr_response_node.children[i]);
    }

    sigma_verified
}

/// Helper to recursively extract monomials from the verifier tree and insert into a hashmap.
fn extract_monomials<T: PrimInt + Hash>(verifier_node: &MonomialVerifierTreeNode, curr_tag: T, dimension: u32, element_commitment_map: &mut HashMap<T, RistrettoPoint>) {
    match verifier_node.commitment {
        None => {},
        Some(c) => {
            element_commitment_map.insert(curr_tag, c);
        }
    }

    let offset = T::zero().count_zeros() - curr_tag.leading_zeros();
    for (i, verifier_child) in verifier_node.children.iter().enumerate() {
        let new_tag = curr_tag | (T::one() << (offset as usize + i));
        extract_monomials(verifier_child, new_tag, dimension, element_commitment_map);
    }
}

/// Generate a map of monomials from the verifier tree.
fn gen_monomial_map<T: PrimInt + Hash>(verifier_trees: &Vec<MonomialVerifierTreeNode>, dimension: u32, commitment_map: &mut HashMap<T, RistrettoPoint>) {

    for verifier_root in verifier_trees {
        let mut element_commitment_map: HashMap<T, RistrettoPoint> = HashMap::new();
        extract_monomials(verifier_root, T::zero(), dimension, &mut element_commitment_map);

        for (k, v) in element_commitment_map {
            if commitment_map.contains_key(&k) {
                let c = commitment_map.get(&k).unwrap();
                commitment_map.insert(k, c + v);
            } else {
                commitment_map.insert(k, v);
            }
        }
    }
}

/// Dishonest commitment phase: read bit sigma and product sigma commitment messages from prover and generate matching challenges.
fn verifier_dishonest_commitment_phase<T>(state: &mut VerifierState<T>, stream: &mut TcpStream, db_size: u32, dimension: u32) -> bool
where T: PrimInt + Eq + Hash + DeserializeOwned
{
    // run challenge phase for each incoming commitment

    let mut db_bit_sigma_verifiers: Vec<Vec<bit_sigma::Verifier>> = Vec::new();
    let mut monomial_product_sigma_verifiers: Vec<MonomialVerifierTreeNode> = Vec::new();

    let mut challenge_messages = Vec::new();

    for _i in 0..db_size {
        //eprintln!("  challenging entry     {}/{}", _i+1, db_size);

        let mut element_bit_sigma_verifiers: Vec<bit_sigma::Verifier> = Vec::new();
        let mut element_bit_sigma_challenges: Vec<bit_sigma::Challenge> = Vec::new();

        let bit_sigma_comm_m: BitSigmaCommitmentMessage = serde_json::from_slice(
            &read_from_stream(stream)
        ).unwrap();

        for j in 0..dimension {
            let (sigma_verifier, sigma_challenge) = bit_sigma::challenge(&mut state.rng, &bit_sigma_comm_m.commitments[j as usize]);
            element_bit_sigma_verifiers.push(sigma_verifier);
            element_bit_sigma_challenges.push(sigma_challenge);
        }
        db_bit_sigma_verifiers.push(element_bit_sigma_verifiers);

        challenge_messages.push(serde_json::to_vec(&BitSigmaChallengeMessage {
            challenges: element_bit_sigma_challenges
        }).unwrap());

        if dimension == 1 {
            continue;
        }

        let mut verifier_root = MonomialVerifierTreeNode {
            commitment: None,
            product_sigma_verifier: None,
            children: Vec::new(),
        };

        let mut challenge_root = MonomialChallengeTreeNode {
            product_sigma_challenge: None,
            children: Vec::new(),
        };

        let comm_node: MonomialCommitmentTreeNode = serde_json::from_slice(
            &read_from_stream(stream)
        ).unwrap();

        gen_challenge_tree(state, &comm_node, &mut verifier_root, &mut challenge_root);
        monomial_product_sigma_verifiers.push(verifier_root);

        challenge_messages.push(serde_json::to_vec(&challenge_root).unwrap());
    }

    for msg in challenge_messages {
        write_to_stream(
            stream, &msg
        );
    }

    let mut success = true;

    for i in 0..db_size as usize {
        //eprintln!("  verifying entry     {}/{}", i+1, db_size);

        let resp_m: BitSigmaResponseMessage = serde_json::from_slice(
            &read_from_stream(stream)
        ).unwrap();

        let _start = Instant::now();
        for (j, resp) in resp_m.responses.iter().enumerate() {
            let sigma_verified = bit_sigma::verify(&state.pedersen_pp, &mut db_bit_sigma_verifiers[i][j], &resp);
            if !sigma_verified {
                eprintln!("ERROR: Bit sigma verification failed");
                success = false;
                break;
            }
        }
        if !success {
            break;
        }
        state.comm_verify_duration += _start.elapsed();

        if dimension == 1 {
            continue;
        }

        let resp_node: MonomialResponseTreeNode = serde_json::from_slice(
            &read_from_stream(stream)
        ).unwrap();

        if !verify_response_tree(&state.pedersen_pp, &mut monomial_product_sigma_verifiers[i], &resp_node) {
            eprintln!("ERROR: Monomial product sigma verification failed");
            success = false;
            break;
        }
        if !success {
            break;
        }
    }
        
    write_to_stream(
        stream, &serde_json::to_vec(&VerifierCheckMessage {success}).unwrap()
    );
    
    if !success {
        return false;
    }

    if dimension == 1 {
        let mut sum = RistrettoPoint::default();
        for i in 0..db_size {
            sum += db_bit_sigma_verifiers[i as usize][0].b_comm;
        }
        state.monomial_commitments.insert(T::one(), sum);
    } else {
        gen_monomial_map(&monomial_product_sigma_verifiers, dimension, &mut state.monomial_commitments);
    }
    
    true
}

///
/// -- RANDOMNESS PHASE --
///

/// Randomness phase: coin flip and bit sigma challenge generation; send results back to prover.
fn verifer_randomness_phase_challenge<T: PrimInt + Hash>(state: &mut VerifierState<T>, stream: &mut TcpStream) {

    let _cf_start = Instant::now();
    state.player_b = state.rng.gen_range(0..2);
    state.randomness_coin_flip_agg_duration += _cf_start.elapsed();

    let m: ProverRandomnessComm = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();

    let _start = Instant::now();
    let (sigma_verifier, sigma_challenge) = bit_sigma::challenge(&mut state.rng, &m.commitment);

    state.sigma_verifier = sigma_verifier;
    state.randomness_bit_sigma_verify_duration += _start.elapsed();

    write_to_stream(
        stream, &serde_json::to_vec(&VerifierRandomnessChallenge {
            player_b: state.player_b,
            sigma_challenge
        }).unwrap()
    );
}

/// Randomness phase: check prover responses
fn verifier_randomness_phase_check<T: PrimInt + Hash>(state: &mut VerifierState<T>, stream: &mut TcpStream) -> Option<RistrettoPoint> {

    let resp_msg: ProverRandomnessResponse = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();

    let _cf_start = Instant::now();
    if state.player_b == 0 {
        if resp_msg.final_commitment != state.sigma_verifier.b_comm{
            eprintln!("ERROR: player_b = 0, final_commitment != b_comm");
            write_to_stream(
                stream, &serde_json::to_vec(&VerifierCheckMessage {success: false}).unwrap()
            );
            return None;
        }
    } else {
        if resp_msg.final_commitment != state.C1 + state.sigma_verifier.b_comm.neg() {
            eprintln!("ERROR: player_b = 1, final_commitment != C1 + dealer_b_comm.neg()");
            write_to_stream(
                stream, &serde_json::to_vec(&VerifierCheckMessage {success: false}).unwrap()
            );
            return None;
        }
    }
    state.randomness_coin_flip_agg_duration += _cf_start.elapsed();

    let _start = Instant::now();
    let sigma_verified = bit_sigma::verify(&state.pedersen_pp, &mut state.sigma_verifier, &resp_msg.sigma_response);
    state.randomness_bit_sigma_verify_duration += _start.elapsed();

    write_to_stream(
        stream, &serde_json::to_vec(&VerifierCheckMessage {success: sigma_verified}).unwrap()
    );

    if sigma_verified {
        Some(resp_msg.final_commitment)
    } else {
        None
    }    
}

/// Randomness phase: adjust commitment based on the adjustment factor
fn verifier_randomness_phase_adjust<T: PrimInt + Hash>(state: &mut VerifierState<T>, db_size: u32, epsilon: f32, delta: Option<f32>) {
    let adjustment_factor = Scalar::from((get_n(db_size, epsilon, delta)/2) as u32);
    state.randomness_bit_comm -= pedersen::commit_with_r(&adjustment_factor, &state.CPROOF, &state.pedersen_pp);
}

///
/// -- QUERYING PHASE --
///

/// Generate a random query polynomial with a given sparsity, choosing random monomials and coefficients
fn verifier_gen_random_query<T: PrimInt + Eq + Hash + Copy>(state: &mut VerifierState<T>, sparsity: u32) -> HashMap<T, Scalar> {

    let mut coefficients: HashMap<T, Scalar> = HashMap::new();
    for _ in 0..sparsity {
        if sparsity > state.monomial_commitments.len() as u32 {
            eprintln!("ERROR: Query sparsity ({}) to large for monomial commitments size ({})", sparsity, state.monomial_commitments.len());
        }

        let mut random_id = state.monomial_commitments.keys().choose(&mut state.rng).unwrap();
        while coefficients.contains_key(random_id) {
            random_id = state.monomial_commitments.keys().choose(&mut state.rng).unwrap();
        }
        let coeff = Scalar::random(&mut state.rng);
        coefficients.insert(*random_id, coeff);
    }

    coefficients
}

/// OR together a vector of integers
fn or_vector(a: &Vec<u32>) -> u32 {
    let mut result = 0;
    for i in a {
        result |= i;
    }
    result
}

/// Generate a query polynomial for an income-thresholding query, using the inclusion-exclusion
/// principle to generate coefficients s.t. it will count any DB entries with any bits set in a
/// range.
fn verifier_gen_census_query<T: PrimInt + Eq + Hash + Copy>() -> HashMap<T, Scalar> {

    let mut coefficients: HashMap<T, Scalar> = HashMap::new();

    //let bit_patterns: Vec<u32> = vec![0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000];
    let bit_patterns: Vec<u32> = vec![0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000];

    // 6 choose 1, 2, 3, 4, 5, 6
    for choose in 1..7 {
        let combinations = bit_patterns.clone().into_iter().combinations(choose);
        let coefficient = if choose % 2 == 1 { Scalar::ONE } else { Scalar::ONE.neg() };
        for c in combinations {
            coefficients.insert(T::from(or_vector(&c)).unwrap(), coefficient);
        }
    }

    coefficients
}

fn verifier_send_query<T: PrimInt + Hash>(_state: &mut VerifierState<T>, stream: &mut TcpStream, query_coefficients: &HashMap<T, Scalar>)
where T: Eq + Hash + Clone + Serialize
{
    let m = QueryMessage::<T> {
        coefficients: query_coefficients.clone()
    };
    write_to_stream(
        stream, &serde_json::to_vec(&m).unwrap()
    );
}

/// Having received a response from the prover, verify the query commitments
fn verifier_check_query<T: PrimInt + Hash>(state: &mut VerifierState<T>, stream: &mut TcpStream, query_coefficients: &HashMap<T, Scalar>, print_query_answer: bool) -> (bool, Duration, Duration)
where T: Eq + Hash + Display
{
    let mut query_comm = state.randomness_bit_comm;

    let start_homomorphic = Instant::now();
    for monomial_id in query_coefficients.keys() {
        if !state.monomial_commitments.contains_key(monomial_id) {
            eprintln!("ERROR: Monomial ID {} not found in monomial commitment map", monomial_id);
            return (false, Duration::from_secs(0), Duration::from_secs(0));
        }

        let monomial_comm = state.monomial_commitments.get(monomial_id).unwrap();
        let monomial_coefficient = query_coefficients.get(monomial_id).unwrap();

        query_comm += monomial_coefficient * monomial_comm;
    }
    let duration_homomorphic = start_homomorphic.elapsed();

    let query_answer_m: QueryAnswerMessage = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();

    let query_answer = query_answer_m.answer;
    let query_proof = query_answer_m.proof;

    // measure verification check
    let start_verify = Instant::now();
    let result = pedersen::verify(&query_comm, &query_answer, &query_proof, &state.pedersen_pp);
    let duration_verify = start_verify.elapsed();
    if result && print_query_answer {
        eprintln!("\nQUERY ANSWER:\n\t{:?}\n\n", query_answer.to_bytes());
    } else if !result {
        println!("Query INVALID :(");
    }

    (result, duration_homomorphic, duration_verify)
}

/// Synchronize with the prover to ensure both parties are ready to proceed.
fn synchronize_prover(stream: &mut TcpStream) {
    write_to_stream(
        stream, &serde_json::to_vec(&ReadyMessage { ready: true }).unwrap()
    );
    let _prover_ready: ReadyMessage = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();
}

/// Main function to run the verifier protocol.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // number of elements in the database
    #[arg(long)]
    db_size: u32,

    // differential privacy epsilon
    #[arg(long)]
    epsilon: f32,

    // (optional) differential privacy delta
    #[arg(long, default_value = None)]
    delta: Option<f32>,

    // sparsity -- aka max coefficients in query polynomial
    #[arg(long)]
    sparsity: u32,

    // prover address
    #[arg(long)]
    prover_address: String,

    // dimension
    #[arg(long, default_value_t = size_of::<DataT>() as u32 * 8)]
    dimension: u32,

    // (optional) skip dishonest commitment phase if we're measuring something else
    #[arg(long, default_value_t = false)]
    skip_dishonest: bool,

    // (optional) number of queries to execute and average runtime over
    #[arg(long, default_value_t = 100)]
    num_queries: u32,

    // (optional) evaluate sparsity experiment
    #[arg(long, default_value_t = false)]
    sparsity_experiment: bool,

    // (optional) run census query experiment
    #[arg(long, default_value_t = false)]
    census_query: bool,
}

fn main() {

    eprintln!("Running");

    let args = Args::parse();
    println!("\n-- Verifier --\n");
    println!("Configuration:");
    println!("\tDatabase size: {}", args.db_size);
    println!("\tDimension: {}", args.dimension);
    println!("\tEpsilon: {}", args.epsilon);
    println!("\tDelta: {:?}", args.delta);
    println!("\tSparsity: {}", args.sparsity);
    println!("\tProver address: {}\n", args.prover_address);

    // Setup
    eprintln!("Setup phase start");

    let addr = args.prover_address.parse::<SocketAddr>().unwrap();
    let mut stream = TcpStream::connect_timeout(
        &addr,
        Duration::from_secs(10)
    ).unwrap();

    let mut verifier_state = verifier_setup::<DataT>(&mut stream);
    
    eprintln!("Setup phase complete");

    // Honest Commitment Phase
    eprintln!("Honest commitment phase start");
   
    synchronize_prover(&mut stream);
    let start_honest_comm = Instant::now();
    verifier_honest_commitment_phase(&mut verifier_state, &mut stream);
    synchronize_prover(&mut stream);
    let duration_honest_comm = start_honest_comm.elapsed();
   
    eprintln!("Honest commitment phase complete ({:?})", duration_honest_comm);

    let mut duration_dishonest_comm = Duration::from_secs(0);
    if !args.skip_dishonest {
        // clear out the monomial commitments for the dishonest phase
        verifier_state.monomial_commitments.clear();

        // Dishonest Commitment Phase
        eprintln!("Dishonest commitment phase start");
    
        synchronize_prover(&mut stream);
        let start_dishonest_comm = Instant::now();
        let comm_success = verifier_dishonest_commitment_phase(&mut verifier_state, &mut stream, args.db_size, args.dimension);
        synchronize_prover(&mut stream);
        duration_dishonest_comm = start_dishonest_comm.elapsed();

        if !comm_success {
            return;
        }
    
        eprintln!("Dishonest commitment phase complete ({:?})", duration_dishonest_comm);
    }
    
    // Randomness Phase
    eprintln!("Randomness phase start");

    synchronize_prover(&mut stream);
    let start_rnd = Instant::now();
    verifier_state.randomness_bit_comm = verifier_state.C0;

    for _ in 0..get_n(args.db_size, args.epsilon, args.delta) {
        verifer_randomness_phase_challenge(&mut verifier_state, &mut stream);
        match verifier_randomness_phase_check(&mut verifier_state, &mut stream) {
            Some(c) => {
                let _agg_start = Instant::now();
                verifier_state.randomness_bit_comm += c;
                verifier_state.randomness_coin_flip_agg_duration += _agg_start.elapsed();
            },
            None => {
                println!("ERROR: Randomness phase failed");
                return;
            }
        }
    }
    verifier_randomness_phase_adjust(&mut verifier_state, args.db_size, args.epsilon, args.delta);
    synchronize_prover(&mut stream);
    let duration_rnd = start_rnd.elapsed();

    eprintln!("Randomness phase complete ({:?})", duration_rnd);

    // Query phase
    eprintln!("Query phase start");

    let mut duration_query = Duration::from_secs(0);
    let mut homomorphic_duration = Duration::from_secs(0);
    let mut check_duration = Duration::from_secs(0);

    for _ in 0..args.num_queries {
        let query_coefficients = if args.census_query {
            verifier_gen_census_query()
        } else {
            verifier_gen_random_query(&mut verifier_state, args.sparsity)
        };
        synchronize_prover(&mut stream);
        let iter_start_query = Instant::now();
        verifier_send_query(&mut verifier_state, &mut stream, &query_coefficients);
        let (_success, iter_homomorphic_duration, iter_check_duration) = 
            verifier_check_query(&mut verifier_state, &mut stream, &query_coefficients, args.census_query);
        synchronize_prover(&mut stream);
        let iter_duration_query = iter_start_query.elapsed();

        duration_query += iter_duration_query;
        homomorphic_duration += iter_homomorphic_duration;
        check_duration += iter_check_duration;
    }
    duration_query /= args.num_queries;
    homomorphic_duration /= args.num_queries;
    check_duration /= args.num_queries;

    eprintln!("Query phase complete ({:?})", duration_query);

    if args.sparsity_experiment {
        eprintln!("Sparsity experiment start");
        println!("=== Begin Sparsity Experiment ===\n");

        for s in 1..pow(2, args.dimension as usize) {
            let mut sparsity_homomorphic_duration = Duration::from_secs(0);
            let mut sparsity_check_duration = Duration::from_secs(0);

            for _ in 0..args.num_queries {
                let query_coefficients = verifier_gen_random_query(&mut verifier_state, s);
                synchronize_prover(&mut stream);
                verifier_send_query(&mut verifier_state, &mut stream, &query_coefficients);
                let (_success, s_homomorphic_duration, s_check_duration) = 
                    verifier_check_query(&mut verifier_state, &mut stream, &query_coefficients, false);
                synchronize_prover(&mut stream);

                sparsity_homomorphic_duration += s_homomorphic_duration;
                sparsity_check_duration += s_check_duration;
            }
            sparsity_homomorphic_duration /= args.num_queries;
            sparsity_check_duration /= args.num_queries;
            println!("{:?},{:?},{:?}", s, sparsity_homomorphic_duration.as_secs_f32(), sparsity_check_duration.as_secs_f32());
        }

        println!("\n=== End Sparsity Experiment ===\n");
        eprintln!("Sparsity experiment complete");
    }

    ptable!(
        ["Comparison", "V-Dishonest Comm.", "V-Rand. Gen.", "Rand N +", "Query Verify"],
        ["", format!("{:?} s", verifier_state.comm_verify_duration.as_secs_f32()), format!("{:?} s", verifier_state.randomness_bit_sigma_verify_duration.as_secs_f32()), format!("{:?} s", verifier_state.randomness_coin_flip_agg_duration.as_secs_f32()), format!("{:?} µs", check_duration.as_micros())]
    );

    ptable!(
        ["Verifier", format!("(n={}, d={}, ε={}, δ={:?} s={})", args.db_size, args.dimension, args.epsilon, get_delta(args.db_size, args.delta), args.sparsity)],
        ["Commit", ""],
        ["  -> Honest", format!("{:?}", duration_honest_comm)],
        ["  -> Dishonest", format!("{:?}", duration_dishonest_comm)],
        ["Randomness", format!("{:?}", duration_rnd)],
        ["Query", format!("{:?}", duration_query)],
        ["  -> Homomorphic", format!("{:?}", homomorphic_duration)],
        ["  -> Check", format!("{:?}", check_duration)]
    );

    println!("\n\nCSV (s):");
    println!("{},{},{},{},{},{}", duration_honest_comm.as_secs_f32(), duration_dishonest_comm.as_secs_f32(), duration_rnd.as_secs_f32(), duration_query.as_secs_f32(), homomorphic_duration.as_secs_f32(), check_duration.as_secs_f32());
}