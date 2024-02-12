#[macro_use] extern crate prettytable;

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
use std::net::{TcpStream, TcpListener};
use std::ops::Neg;
use std::time::{Duration, Instant};

use vdp_poc::config::{get_n, get_delta, PROVER_ADDRESS, PROVER_PORT, DataT};
use vdp_poc::data::Data;
use vdp_poc::messages::{read_from_stream, write_to_stream, BitSigmaChallengeMessage, BitSigmaCommitmentMessage, BitSigmaResponseMessage, CommitmentMapMessage, MonomialChallengeTreeNode, MonomialCommitmentTreeNode, MonomialResponseTreeNode, ProverRandomnessComm, ProverRandomnessResponse, QueryAnswerMessage, QueryMessage, ReadyMessage, SetupMessage, VerifierCheckMessage, VerifierRandomnessChallenge};
use vdp_poc::pedersen;
use vdp_poc::bit_sigma;
use vdp_poc::product_sigma;

#[allow(non_snake_case)]
struct ProverState {
    rng: OsRng,
    pedersen_pp: pedersen::PublicParams,
    dealer_b: u32,
    dealer_b_comm: RistrettoPoint,
    dealer_b_proof: Scalar,
    final_b: u32,
    final_proof: Scalar,
    randomness_bit_sum: Scalar,
    randomness_bit_proof: Scalar,
    sigma_prover: bit_sigma::Prover,
    C1: RistrettoPoint,
    CPROOF: Scalar,

    randomness_sigma_duration: Duration,
    coin_flipping_and_agg_duration: Duration,
}

//
// -- SETUP PHASE --
//

fn prover_setup(stream: &mut TcpStream) -> ProverState {

    let mut rng = OsRng::default();
    let prover_seed = rng.gen::<[u8; 32]>();

    let mut shared_rng = ChaCha20Rng::from_seed(prover_seed);
    let pp = pedersen::setup(&mut shared_rng);

    let proof_val = Scalar::from(0 as u32);

    write_to_stream(
        stream, &serde_json::to_vec(&SetupMessage {
            seed: prover_seed
        }).unwrap()
    );

    ProverState {
        rng,
        pedersen_pp: pp.clone(),
        C1: pedersen::commit_with_r(&Scalar::from(1 as u32), &proof_val, &pp),
        CPROOF: proof_val,
        dealer_b: 0,
        dealer_b_comm: RistrettoPoint::default(),
        dealer_b_proof: Scalar::default(),
        final_b: 0,
        final_proof: Scalar::default(),
        randomness_bit_sum: Scalar::default(),
        randomness_bit_proof: Scalar::default(),
        sigma_prover: bit_sigma::Prover::default(),

        randomness_sigma_duration: Duration::from_secs(0),
        coin_flipping_and_agg_duration: Duration::from_secs(0),
    }
}

//
// -- COMMITMENT PHASE --
//

#[allow(dead_code)]
fn calculate_monomial_sum<T: PrimInt>(indices: T, data: &[T]) -> Scalar {
    let inv_indices = !indices;
    let mut cnt: u32 = 0;
    for i in 0..data.len() {
        if (data[i] | inv_indices).count_zeros() == 0 { 
            cnt += 1;
        }
    }
    Scalar::from(cnt)
}

#[allow(dead_code)]
fn generate_monomial_sums_helper<T: PrimInt + Hash>(indices: T, current_idx: T, data: &[T], monomial_map: &mut HashMap<T, Scalar>,
                                                    dimension: u32, max_degree: u32) {

    // we've recursively set bits for the bitwidth of the database entry type OR the max configured degree (number of set bits)
    if current_idx.to_u32().unwrap() == dimension || indices.count_ones() == max_degree {
        // skip the empty monomial
        if indices.count_ones() > 0 {
            let sum = calculate_monomial_sum(indices, data);
            monomial_map.insert(indices, sum);
        }
        return;
    }

    // set bit at current index to a 0 or 1 and recurse
    generate_monomial_sums_helper(
        indices, current_idx + T::one(), data, monomial_map, dimension, max_degree);
    generate_monomial_sums_helper(
        indices | (T::one() << current_idx.to_usize().unwrap()), current_idx + T::one(), data, monomial_map, dimension, max_degree);
}

#[allow(dead_code)]
fn generate_monomial_sums<T: PrimInt + Hash>(data: &[T], dimension: u32, max_degree: u32) -> HashMap<T, Scalar> {
    let mut map = HashMap::new();
    generate_monomial_sums_helper(T::zero(), T::zero(), data, &mut map, dimension, max_degree);
    map
}

#[allow(dead_code)]
fn prover_honest_commitment_phase<T: PrimInt + Hash + Serialize>(state: &mut ProverState, stream: &mut TcpStream, database: &mut Data<T>, dimension: u32, max_degree: u32) {

    let mut m = CommitmentMapMessage::<T> {
        commitment_map: HashMap::new()
    };

    for (monomial_id, monomial_sum) in generate_monomial_sums(&database.entries, dimension, max_degree) {
        let (comm, proof) = pedersen::commit(&mut state.rng, &monomial_sum, &state.pedersen_pp);
        database.commitments.insert(monomial_id, (monomial_sum, comm, proof));
        m.commitment_map.insert(monomial_id, comm);
    }

    write_to_stream(
        stream, &serde_json::to_vec(&m).unwrap()
    );
}

pub struct MonomialProverTreeNode {
    pub commitment: Option<(Scalar, RistrettoPoint, Scalar)>,
    pub product_sigma_prover: Option<product_sigma::Prover>,
    pub children: Vec<Box<MonomialProverTreeNode>>,
}

fn gen_monomial_tree(state: &mut ProverState, entry_bit_commitments: &Vec<(Scalar, RistrettoPoint, Scalar)>,
                     curr_nodes: (&mut MonomialProverTreeNode, &mut MonomialCommitmentTreeNode),
                     curr_idx: isize, curr_degree: usize, dimension: usize, max_degree: usize) {

    // base case: if we get to the data dimension size or generate a monomial of max degree, we're done 
    if curr_idx == dimension as isize || curr_degree == max_degree {
        return;
    } 

    let (curr_prover_node, curr_comm_node) = curr_nodes;
    
    // recursive cases: add indices greater than curr_idx to the current monomial and recurse
    for i in (curr_idx + 1) as usize..dimension {
        let mut prover_child = MonomialProverTreeNode {
            commitment: None,
            product_sigma_prover: None,
            children: Vec::new(),
        };

        let mut comm_child = MonomialCommitmentTreeNode {
            commitment: None,
            product_sigma_commitment: None,
            children: Vec::new(),
        };

        match curr_prover_node.commitment {
            None => {
                prover_child.commitment = Some(entry_bit_commitments[i]);
                comm_child.commitment = Some(entry_bit_commitments[i].1);
            },
            Some((m_1, c_1, r_1)) => {
                let (m_2, c_2, r_2) = entry_bit_commitments[i];
                let m_3 = m_1 * m_2;
                let (c_3, r_3) = pedersen::commit(&mut state.rng, &m_3, &state.pedersen_pp);

                let (prover, commitment) = product_sigma::commit(&mut state.rng, &state.pedersen_pp, (m_1, c_1, r_1), (m_2, c_2, r_2), (m_3, c_3, r_3));

                prover_child.commitment = Some((m_3, c_3, r_3));
                prover_child.product_sigma_prover = Some(prover);

                comm_child.commitment = Some(c_3);
                comm_child.product_sigma_commitment = Some(commitment);
            }
        };

        gen_monomial_tree(state, entry_bit_commitments, (&mut prover_child, &mut comm_child), i as isize, curr_degree + 1, dimension, max_degree);

        curr_prover_node.children.push(Box::new(prover_child));
        curr_comm_node.children.push(Box::new(comm_child));
    }
}

fn gen_response_tree(state: &mut ProverState, prover_node: &mut MonomialProverTreeNode, challenge_node: &MonomialChallengeTreeNode, response_node: &mut MonomialResponseTreeNode) {
    match &challenge_node.product_sigma_challenge {
        None => {
            response_node.product_sigma_response = None;
        },
        Some(c) => {
            response_node.product_sigma_response = Some(product_sigma::response(&mut prover_node.product_sigma_prover.as_mut().unwrap(), &c));
        }
    };

    for (i, prover_child ) in prover_node.children.iter_mut().enumerate() {
        let mut response_child = MonomialResponseTreeNode {
            product_sigma_response: None,
            children: Vec::new(),
        };

        gen_response_tree(state, prover_child, &challenge_node.children[i], &mut response_child);
        response_node.children.push(Box::new(response_child));
    }
}

fn _count_tree(node: &MonomialProverTreeNode) -> usize {
    let mut count = 1;
    for child in &node.children {
        count += _count_tree(child);
    }
    count
}

fn extract_monomials<T: PrimInt + Hash>(prover_node: &MonomialProverTreeNode, curr_tag: T, dimension: u32, element_commitment_map: &mut HashMap<T, (Scalar, RistrettoPoint, Scalar)>) {
    match prover_node.commitment {
        None => {},
        Some((m, c, r)) => {
            element_commitment_map.insert(curr_tag, (m, c, r));
        }
    }

    let offset = T::zero().count_zeros() - curr_tag.leading_zeros();
    for (i, prover_child) in prover_node.children.iter().enumerate() {
        let new_tag = curr_tag | (T::one() << (offset as usize + i));
        extract_monomials(prover_child, new_tag, dimension, element_commitment_map);
    }
}

fn gen_monomial_map<T: PrimInt + Hash>(prover_trees: &Vec<MonomialProverTreeNode>, dimension: u32, commitment_map: &mut HashMap<T, (Scalar, RistrettoPoint, Scalar)>) {

    for prover_root in prover_trees {
        let mut element_commitment_map: HashMap<T, (Scalar, RistrettoPoint, Scalar)> = HashMap::new();
        extract_monomials(prover_root, T::zero(), dimension, &mut element_commitment_map);
        //eprintln!("  element commitment map: {:?}", element_commitment_map.len());

        for (k, v) in element_commitment_map {
            if commitment_map.contains_key(&k) {
                let (m, c, r) = commitment_map.get(&k).unwrap();
                commitment_map.insert(k, (m + v.0, c + v.1, r + v.2));
            } else {
                commitment_map.insert(k, v);
            }
        }
    }
}

fn prover_dishonest_commitment_phase<T: PrimInt + Hash + Serialize>(state: &mut ProverState, stream: &mut TcpStream, database: &mut Data<T>, dimension: u32, max_degree: u32) -> bool {

    // Per-database entry bit sigma protocols
    let mut db_bit_sigma_provers: Vec<Vec<bit_sigma::Prover>> = Vec::new();
    // Forest of monomial trees per-database element
    let mut monomial_prover_trees: Vec<MonomialProverTreeNode> = Vec::new();

    for (i, entry) in database.entries.iter().enumerate() {
        eprintln!("  committing to entry   {}/{}", i+1, database.entries.len());

        let mut entry_commitments: Vec<(Scalar, RistrettoPoint, Scalar)> = Vec::new();
        let mut entry_sigma_provers: Vec<bit_sigma::Prover> = Vec::new();
        let mut entry_sigma_commitments : Vec<bit_sigma::Commitment> = Vec::new();

        let bit_sigma_start = Instant::now();
        for i in 0..dimension {
            let mask = T::one() << (i as usize);

            let bit: u32 = if entry.bitand(mask) == mask { 1 } else { 0 };
            let (comm, proof) = pedersen::commit(&mut state.rng, &Scalar::from(bit), &state.pedersen_pp);
            let (prover, commitment) = bit_sigma::commit(&mut state.rng, &state.pedersen_pp, bit, comm, proof);

            entry_commitments.push((Scalar::from(bit), comm, proof));
            entry_sigma_provers.push(prover);
            entry_sigma_commitments.push(commitment);
        }    
        let _bit_sigma_duration = bit_sigma_start.elapsed();

        db_bit_sigma_provers.push(entry_sigma_provers);

        // send the entry bit sigma commitments to the verifier
        write_to_stream(
            stream, &serde_json::to_vec(&BitSigmaCommitmentMessage {
                commitments: entry_sigma_commitments
            }).unwrap()
        );

        let mut entry_prover_root = MonomialProverTreeNode {
            commitment: None,
            product_sigma_prover: None,
            children: Vec::new(),
        };

        let mut entry_commitment_root = MonomialCommitmentTreeNode {
            commitment: None,
            product_sigma_commitment: None,
            children: Vec::new(),
        };

        let monomial_tree_start = Instant::now();
        gen_monomial_tree(state, &entry_commitments, (&mut entry_prover_root, &mut entry_commitment_root), -1, 0, dimension as usize, max_degree as usize);
        let _monomial_tree_duration = monomial_tree_start.elapsed();

        monomial_prover_trees.push(entry_prover_root);

        // send entry monomial tree to the prover
        write_to_stream(
            stream, &serde_json::to_vec(&entry_commitment_root).unwrap()
        )
    }

    let mut response_messages = Vec::new();

    for i in 0..database.entries.len() {
        eprintln!("  responding to entry {}/{}", i+1, database.entries.len());

        let challenge_m: BitSigmaChallengeMessage = serde_json::from_slice(
            &read_from_stream(stream)
        ).unwrap();

        let mut entry_responses: Vec<bit_sigma::Response> = Vec::new();
        for (bit_idx, m) in challenge_m.challenges.iter().enumerate() {
            let response = bit_sigma::response(&mut db_bit_sigma_provers[i][bit_idx], m);
            entry_responses.push(response);
        }

        let resp_mesg = serde_json::to_vec(&BitSigmaResponseMessage {
            responses: entry_responses
        }).unwrap();
        //response_messages.push(compress(&resp_mesg));
        response_messages.push(resp_mesg);

        let monomial_challenge_root: MonomialChallengeTreeNode = serde_json::from_slice(
            &read_from_stream(stream)
        ).unwrap();

        let mut response_root = MonomialResponseTreeNode {
            product_sigma_response: None,
            children: Vec::new(),
        };
        gen_response_tree(state, &mut monomial_prover_trees[i], &monomial_challenge_root, &mut response_root);

        let resp_root = serde_json::to_vec(&response_root).unwrap();
        response_messages.push(resp_root);
    }

    for m in response_messages {
        write_to_stream(stream, &m);
    }

    let check_m: VerifierCheckMessage = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();

    if !check_m.success {
        eprintln!("ERROR: Commitment phase failed");
        return false;
    } else {
        eprintln!("  check successful");
    }

    gen_monomial_map(&monomial_prover_trees, dimension, &mut database.commitments);

    true
}

//
// -- RANDOMNESS PHASE --
//

fn prover_randomness_phase_comm(state: &mut ProverState, stream: &mut TcpStream) {

    let dealer_b: u32 = state.rng.gen_range(0..2);
    let (dealer_b_comm, dealer_b_proof) =
        pedersen::commit(&mut state.rng, &Scalar::from(dealer_b), &state.pedersen_pp);

    let (sigma_prover, sigma_commitment) = 
        bit_sigma::commit(&mut state.rng, &state.pedersen_pp, dealer_b, dealer_b_comm, dealer_b_proof);

    state.sigma_prover = sigma_prover;
    state.dealer_b = dealer_b;
    state.dealer_b_comm = dealer_b_comm;
    state.dealer_b_proof = dealer_b_proof;

    write_to_stream(
        stream, &serde_json::to_vec(&ProverRandomnessComm {
            commitment: sigma_commitment
        }).unwrap()
    );
}

fn prover_randomness_phase_response(state: &mut ProverState, stream: &mut TcpStream) -> bool {

    let final_commitment: RistrettoPoint;
    let final_proof: Scalar;
    let final_b: u32;

    let m: VerifierRandomnessChallenge = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();

    if m.player_b == 0 {
        final_commitment = state.dealer_b_comm;
        final_proof = state.dealer_b_proof;
        final_b = state.dealer_b;
    } else {
        final_commitment = state.C1 + state.dealer_b_comm.neg();
        final_proof = state.CPROOF + state.dealer_b_proof.neg();

        final_b = 1 - state.dealer_b;
    }

    state.final_b = final_b;
    state.final_proof = final_proof;

    write_to_stream(
        stream, &serde_json::to_vec(&ProverRandomnessResponse {
            final_commitment,
            sigma_response: bit_sigma::response(&mut state.sigma_prover, &m.sigma_challenge)
        }).unwrap()
    );

    let result: VerifierCheckMessage = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();
    result.success
}

fn prover_randomness_phase_adjust(state: &mut ProverState, db_size: u32, epsilon: f32, delta: Option<f32>) {
    let adjustment_factor = Scalar::from((get_n(db_size, epsilon, delta)/2) as u32);
    state.randomness_bit_sum -= adjustment_factor;
    state.randomness_bit_proof -= state.CPROOF;
}

//
// -- QUERYING PHASE --
//

fn prover_answer_query<T>(state: &mut ProverState, database: &mut Data<T>, stream: &mut TcpStream)
where T: Eq + Hash + Display + DeserializeOwned
{
    let query_m: QueryMessage<T> = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();

    let mut query_answer = state.randomness_bit_sum;
    let mut query_proof = state.randomness_bit_proof;

    for monomial_id in query_m.coefficients.keys() {
        if !database.commitments.contains_key(monomial_id) {
            eprintln!("ERROR: Monomial ID {} not found in monomial map", monomial_id);
            return;
        }

        let (monomial_sum, _monomial_comm, monomial_proof) = database.commitments.get(monomial_id).unwrap();
        let monomial_coefficient = query_m.coefficients.get(monomial_id).unwrap();

        query_answer += monomial_coefficient * monomial_sum;
        query_proof += monomial_coefficient * monomial_proof;
    }

    write_to_stream(
        stream,
        &serde_json::to_vec(&QueryAnswerMessage {
            answer: query_answer,
            proof: query_proof
        }).unwrap()
    );
}

fn synchronize_verifier(stream: &mut TcpStream) {
    let _verifier_ready: ReadyMessage = serde_json::from_slice(
        &read_from_stream(stream)
    ).unwrap();
    write_to_stream(
        stream, &serde_json::to_vec(&ReadyMessage { ready: true }).unwrap()
    );
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // number of elements in the database
    #[arg(long)]
    db_size: u32,

    // (optional) dimension override
    #[arg(long, default_value_t = size_of::<DataT>() as u32 * 8)]
    dimension: u32,

    // max monomial degree
    #[arg(long)]
    max_degree: u32,

    // differential privacy epsilon
    #[arg(long)]
    epsilon: f32,

    // (optional) delta parameter
    #[arg(long, default_value = None)]
    delta: Option<f32>,

    // sparsity
    #[arg(long)]
    sparsity: u32,

    // (optional) skip dishonest commitment phase if we're measuring something else
    #[arg(long, default_value_t = false)]
    skip_dishonest: bool,
}

fn main() {

    // P-Rand Gen. == Bit-commit
    //     time for bit sigma in randomness phase
    // randomness_sigma_duration - TODO

    // Rand N-O & Query-O == Agg
    //     time for summing monomials in query answer + adding all the coin flips in that loop
    // coin_flipping_and_agg_duration - TODO

    // Check = verifier checks the query
    eprintln!("Running");

    let args = Args::parse();
    println!("\n-- Prover --\n");
    println!("Configuration:");
    println!("\tDatabase size: {}", args.db_size);
    println!("\tDimension: {}", args.dimension);
    println!("\tMax degree: {}", args.max_degree);
    println!("\tSparsity: {}", args.sparsity);
    println!("\tEpsilon: {}", args.epsilon);
    println!("\tDelta: {:?}", args.delta);
    println!("\tProver address: {}:{}\n", PROVER_ADDRESS, PROVER_PORT);

    // Setup
    eprintln!("Setup phase start");

    let listener = TcpListener::bind(format!("{}:{}", PROVER_ADDRESS, PROVER_PORT)).unwrap();
    let (mut stream, _) = listener.accept().unwrap();

    let mut prover_state = prover_setup(&mut stream);
    let mut database: Data<DataT> = Data::new(&mut prover_state.rng, args.db_size);

    eprintln!("Setup phase complete");

    // Honest Commitment Phase
    eprintln!("Honest commitment phase start");
   
    synchronize_verifier(&mut stream);
    let start_honest_comm = Instant::now();
    prover_honest_commitment_phase(&mut prover_state, &mut stream, &mut database, args.dimension, args.max_degree);
    synchronize_verifier(&mut stream);
    let duration_honest_comm = start_honest_comm.elapsed();

    eprintln!("Honest commitment phase complete ({:?}, {:?} monomials, {:?}/monomial)",
        duration_honest_comm, database.commitments.len(), duration_honest_comm / database.commitments.len() as u32);

    let mut duration_dishonest_comm = Duration::from_secs(0);
    if !args.skip_dishonest {
        // clear out database commitments for next phase
        database.commitments.clear();

        // Dishonest Commitment Phase
        eprintln!("Dishonest commitment phase start");
    
        synchronize_verifier(&mut stream);
        let start_dishonest_comm = Instant::now();
        let comm_success = prover_dishonest_commitment_phase(&mut prover_state, &mut stream, &mut database, args.dimension, args.max_degree);
        synchronize_verifier(&mut stream);
        duration_dishonest_comm = start_dishonest_comm.elapsed();

        if !comm_success {
            return;
        }

        eprintln!("Dishonest commitment phase complete ({:?}, {:?} monomials, {:?}/monomial)",
            duration_dishonest_comm, database.commitments.len(), duration_dishonest_comm / database.commitments.len() as u32);
    }
   
    // Randomness Phase
    eprintln!("Randomness phase start (N: {:?})", get_n(args.db_size, args.epsilon, args.delta));

    synchronize_verifier(&mut stream);
    let start_rnd = Instant::now();
    prover_state.randomness_bit_sum = Scalar::from(0 as u32);
    prover_state.randomness_bit_proof = prover_state.CPROOF;

    for _ in 0..get_n(args.db_size, args.epsilon, args.delta) {
        prover_randomness_phase_comm(&mut prover_state, &mut stream);
        if prover_randomness_phase_response(&mut prover_state, &mut stream) {
            prover_state.randomness_bit_sum += Scalar::from(prover_state.final_b);
            prover_state.randomness_bit_proof += prover_state.final_proof;
        } else {
            println!("ERROR: Randomness phase failed");
            return;
        }
    }
    prover_randomness_phase_adjust(&mut prover_state, args.db_size, args.epsilon, args.delta);
    synchronize_verifier(&mut stream);
    let duration_rnd = start_rnd.elapsed();

    eprintln!("Randomness phase complete ({:?}, N = {} iterations, {:?}/iteration)",
        duration_rnd, get_n(args.db_size, args.epsilon, args.delta), duration_rnd / get_n(args.db_size, args.epsilon, args.delta));

    // Query phase
    eprintln!("Query phase start");

    synchronize_verifier(&mut stream);
    let start_query = Instant::now();
    prover_answer_query(&mut prover_state, &mut database, &mut stream);
    synchronize_verifier(&mut stream);
    let duration_query = start_query.elapsed();

    eprintln!("Query phase complete ({:?})", duration_query);

    ptable!(
        ["Prover", format!("(n={}, d={}, ε={}, δ={:?} s={})", args.db_size, args.dimension, args.epsilon, get_delta(args.db_size, args.delta), args.sparsity)],
        ["Commit", ""],
        ["  -> Honest", format!("{:?}", duration_honest_comm)],
        ["  -> Dishonest", format!("{:?}", duration_dishonest_comm)],
        ["Randomness", format!("{:?}", duration_rnd)],
        ["Query", format!("{:?}", duration_query)]
    );
}
