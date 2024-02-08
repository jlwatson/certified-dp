#[macro_use] extern crate prettytable;

use clap::Parser;
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use num_traits::PrimInt;
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

use vdp_poc::bit_sigma;
use vdp_poc::product_sigma;
use vdp_poc::config::{get_n, get_delta, DataT};
use vdp_poc::messages::{read_from_stream, write_to_stream, CommitmentMapMessage, MonomialChallengeTreeNode, MonomialCommitmentTreeNode, MonomialResponseTreeNode, ProverRandomnessComm, ProverRandomnessResponse, ProverSigmaCommitmentMessage, ProverSigmaResponseMessage, QueryAnswerMessage, QueryMessage, SetupMessage, VerifierCheckMessage, VerifierRandomnessChallenge, VerifierSigmaChallengeMessage};
use vdp_poc::pedersen;

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
}

//
// -- SETUP PHASE --
//

fn verifier_setup<T: PrimInt + Hash>(stream: &mut TcpStream) -> VerifierState<T> {

    let rng = OsRng::default();
   
    let setup_message: SetupMessage = serde_json::from_str(
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
    }
}

//
// -- COMMITMENT PHASE --
//

#[allow(dead_code)]
fn verifier_honest_commitment_phase<T: PrimInt + Hash>(state: &mut VerifierState<T>, stream: &mut TcpStream)
where T: Eq + Hash + DeserializeOwned
{
    let m: CommitmentMapMessage<T> = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    state.monomial_commitments = m.commitment_map;
}

pub struct MonomialVerifierTreeNode {
    pub commitment: Option<RistrettoPoint>,
    pub product_sigma_verifier: Option<product_sigma::Verifier>,
    pub children: Vec<Box<MonomialVerifierTreeNode>>,
}

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

fn extract_monomials<T: PrimInt + Hash>(verifier_node: &MonomialVerifierTreeNode, curr_tag: T, dimension: u32, element_commitment_map: &mut HashMap<T, RistrettoPoint>) {
    match verifier_node.commitment {
        None => {},
        Some(c) => {
            element_commitment_map.insert(curr_tag, c);
        }
    }

    // adjust for dimensions that aren't exactly the size of T
    let remaining_zeros = curr_tag.leading_zeros() - (T::zero().count_zeros() - dimension);
    for (i, verifier_child) in verifier_node.children.iter().enumerate() {
        let new_tag = curr_tag | (T::one() << (remaining_zeros as usize + i));
        extract_monomials(verifier_child, new_tag, dimension, element_commitment_map);
    }
}

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

fn verifier_dishonest_commitment_phase<T>(state: &mut VerifierState<T>, stream: &mut TcpStream, dimension: u32) -> bool
where T: PrimInt + Eq + Hash + DeserializeOwned
{
    let m: ProverSigmaCommitmentMessage = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    // run challenge phase for each commitment
    let mut db_bit_sigma_verifiers: Vec<Vec<bit_sigma::Verifier>> = Vec::new();
    let mut db_bit_sigma_challenges: Vec<Vec<bit_sigma::Challenge>> = Vec::new();

    for element_bit_sigma_comms in m.db_bit_sigma_commitments{
        let mut element_bit_sigma_verifiers: Vec<bit_sigma::Verifier> = Vec::new();
        let mut element_bit_sigma_challenges: Vec<bit_sigma::Challenge> = Vec::new();

        for comm in element_bit_sigma_comms {
            let (sigma_verifier, sigma_challenge) = bit_sigma::challenge(&mut state.rng, &comm);
            element_bit_sigma_verifiers.push(sigma_verifier);
            element_bit_sigma_challenges.push(sigma_challenge);
        }

        db_bit_sigma_verifiers.push(element_bit_sigma_verifiers);
        db_bit_sigma_challenges.push(element_bit_sigma_challenges);
    }

    let mut monomial_product_sigma_verifiers: Vec<MonomialVerifierTreeNode> = Vec::new();
    let mut monomial_product_sigma_challenges: Vec<MonomialChallengeTreeNode> = Vec::new();
        
    for element_product_sigma_root in m.monomial_product_sigma_commitments{
        let mut verifier_root = MonomialVerifierTreeNode {
            commitment: None,
            product_sigma_verifier: None,
            children: Vec::new(),
        };

        let mut challenge_root = MonomialChallengeTreeNode {
            product_sigma_challenge: None,
            children: Vec::new(),
        };

        gen_challenge_tree(state, &element_product_sigma_root, &mut verifier_root, &mut challenge_root);
        monomial_product_sigma_verifiers.push(verifier_root);
        monomial_product_sigma_challenges.push(challenge_root);
    }

    write_to_stream(
        stream, serde_json::to_string(&VerifierSigmaChallengeMessage {
            db_bit_sigma_challenges,
            monomial_product_sigma_challenges
        }).unwrap()
    );

    let resp_msg: ProverSigmaResponseMessage = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    let mut success = true;

    for (i, element_responses) in resp_msg.db_bit_sigma_responses.iter().enumerate() {
        for (j, resp) in element_responses.iter().enumerate() {
            let sigma_verified = bit_sigma::verify(&state.pedersen_pp, &mut db_bit_sigma_verifiers[i][j], &resp);
            if !sigma_verified {
                eprintln!("ERROR: Bit sigma verification failed");
                success = false;
            }
        }
    }

    for (i, element_response_root) in resp_msg.monomial_product_sigma_responses.iter().enumerate() {
        if !verify_response_tree(&state.pedersen_pp, &mut monomial_product_sigma_verifiers[i], &element_response_root) {
            eprintln!("ERROR: Monomial product sigma verification failed");
            success = false;
            break;
        }
    }
    write_to_stream(
        stream, serde_json::to_string(&VerifierCheckMessage {success}).unwrap()
    );
    
    if !success {
        return false;
    }

    gen_monomial_map(&monomial_product_sigma_verifiers, dimension, &mut state.monomial_commitments);

    true
}

//
// -- RANDOMNESS PHASE --
//

fn verifer_randomness_phase_challenge<T: PrimInt + Hash>(state: &mut VerifierState<T>, stream: &mut TcpStream) {

    state.player_b = state.rng.gen_range(0..2);

    let m: ProverRandomnessComm = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    let (sigma_verifier, sigma_challenge) = bit_sigma::challenge(&mut state.rng, &m.commitment);

    state.sigma_verifier = sigma_verifier;

    write_to_stream(
        stream, serde_json::to_string(&VerifierRandomnessChallenge {
            player_b: state.player_b,
            sigma_challenge
        }).unwrap()
    );
}

fn verifier_randomness_phase_check<T: PrimInt + Hash>(state: &mut VerifierState<T>, stream: &mut TcpStream) -> Option<RistrettoPoint> {

    let resp_msg: ProverRandomnessResponse = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

    if state.player_b == 0 {
        if resp_msg.final_commitment != state.sigma_verifier.b_comm{
            eprintln!("ERROR: player_b = 0, final_commitment != b_comm");
            write_to_stream(
                stream, serde_json::to_string(&VerifierCheckMessage {success: false}).unwrap()
            );
            return None;
        }
    } else {
        if resp_msg.final_commitment != state.C1 + state.sigma_verifier.b_comm.neg() {
            eprintln!("ERROR: player_b = 1, final_commitment != C1 + dealer_b_comm.neg()");
            write_to_stream(
                stream, serde_json::to_string(&VerifierCheckMessage {success: false}).unwrap()
            );
            return None;
        }
    }

    let sigma_verified = bit_sigma::verify(&state.pedersen_pp, &mut state.sigma_verifier, &resp_msg.sigma_response);

    write_to_stream(
        stream, serde_json::to_string(&VerifierCheckMessage {success: sigma_verified}).unwrap()
    );

    if sigma_verified {
        Some(resp_msg.final_commitment)
    } else {
        None
    }    
}

fn verifier_randomness_phase_adjust<T: PrimInt + Hash>(state: &mut VerifierState<T>, db_size: u32, epsilon: f32, delta: Option<f32>) {
    let adjustment_factor = Scalar::from((get_n(db_size, epsilon, delta)/2) as u32);
    state.randomness_bit_comm -= pedersen::commit_with_r(&adjustment_factor, &state.CPROOF, &state.pedersen_pp);
}

//
// -- QUERYING PHASE --
//

fn verifier_generate_query<T: PrimInt + Eq + Hash + Copy>(state: &mut VerifierState<T>, sparsity: u32) -> HashMap<T, Scalar> {

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

fn verifier_send_query<T: PrimInt + Hash>(_state: &mut VerifierState<T>, stream: &mut TcpStream, query_coefficients: &HashMap<T, Scalar>)
where T: Eq + Hash + Clone + Serialize
{
    let m = QueryMessage::<T> {
        coefficients: query_coefficients.clone()
    };
    write_to_stream(
        stream, serde_json::to_string(&m).unwrap()
    );
}

fn verifier_check_query<T: PrimInt + Hash>(state: &mut VerifierState<T>, stream: &mut TcpStream, query_coefficients: &HashMap<T, Scalar>) -> (bool, Duration, Duration)
where T: Eq + Hash + Display
{
    let query_answer_m: QueryAnswerMessage = serde_json::from_str(
        &read_from_stream(stream)
    ).unwrap();

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

    let query_answer = query_answer_m.answer;
    let query_proof = query_answer_m.proof;

    // measure verification check
    let start_verify = Instant::now();
    let result = pedersen::verify(&query_comm, &query_proof, &query_answer, &state.pedersen_pp);
    let duration_verify = start_verify.elapsed();
    if result {
        println!("Query verified!");
    } else {
        println!("Query INVALID :(");
    }

    (result, duration_homomorphic, duration_verify)
}

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

    // Commitment Phase
    eprintln!("Commitment phase start");
   
    let start_comm = Instant::now();
    let comm_success = verifier_dishonest_commitment_phase(&mut verifier_state, &mut stream, args.dimension);
    let duration_comm = start_comm.elapsed();

    if !comm_success {
        return;
    }
   
    eprintln!("Commitment phase complete ({:?})", duration_comm);
    
    // Randomness Phase
    eprintln!("Randomness phase start");

    let start_rnd = Instant::now();
    verifier_state.randomness_bit_comm = verifier_state.C0;

    for _ in 0..get_n(args.db_size, args.epsilon, args.delta) {
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
    verifier_randomness_phase_adjust(&mut verifier_state, args.db_size, args.epsilon, args.delta);
    let duration_rnd = start_rnd.elapsed();

    eprintln!("Randomness phase complete ({:?})", duration_rnd);

    // Query generation
    eprintln!("Query generation start");

    let query_coefficients = verifier_generate_query(&mut verifier_state, args.sparsity);
    
    eprintln!("Query generation complete");

    // Query phase
    eprintln!("Query phase start");

    let start_query = Instant::now();
    verifier_send_query(&mut verifier_state, &mut stream, &query_coefficients);
    let (_success, homomorphic_duration, check_duration) = 
        verifier_check_query(&mut verifier_state, &mut stream, &query_coefficients);
    let duration_query = start_query.elapsed();

    eprintln!("Query phase complete ({:?})", duration_query);

    ptable!(
        ["Verifier", format!("(n={}, d={}, ε={}, δ={:?} s={})", args.db_size, args.dimension, args.epsilon, get_delta(args.db_size, args.delta), args.sparsity)],
        ["Commit", format!("{:?}", duration_comm)],
        ["Randomness", format!("{:?}", duration_rnd)],
        ["Query", format!("{:?}", duration_query)],
        ["  -> Homomorphic", format!("{:?}", homomorphic_duration)],
        ["  -> Check", format!("{:?}", check_duration)]
    );
}