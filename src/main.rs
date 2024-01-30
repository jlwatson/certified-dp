#![allow(warnings)]

mod pedersen;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use num_traits::PrimInt;
use pedersen::{setup, commit, commit_with_r, verify, PublicParams};
use rand::rngs::OsRng;
use rand::{Rng, CryptoRng, SeedableRng};
use rand::seq::IteratorRandom;
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::io::{self, Write};
use std::ops::Neg;

use serde::{Serialize, Deserialize};
use serde_json::Result;

// database
const D: u32 = 16;
const TEST_DATA: [u16; 4] = [
    0xdead,
    0xbeef,
    0xdaad,
    0xeebe,
];
const LOG_DATA_LEN: u32 = TEST_DATA.len().ilog2();

// monomial limit
const K: u32 = 2;
const NUM_COEFFICIENTS: usize = 16;

// DP constant
// Generated by setting epsilon to 1 and delta to 1/n^(log n)
const N: usize = 8 * ((LOG_DATA_LEN * LOG_DATA_LEN) + 1) as usize;

#[derive(Serialize, Deserialize, Debug)]
struct SetupMessage {
    seed: [u8; 32]
}

#[derive(Serialize, Deserialize, Debug)]
struct CommitmentMapMessage {
    commitment_map: HashMap<u16, RistrettoPoint>
}

#[derive(Serialize, Deserialize, Debug)]
struct ProverRandomnessComm {
    dealer_b_comm: RistrettoPoint,
    c0: RistrettoPoint,
    c1: RistrettoPoint
}

#[derive(Serialize, Deserialize, Debug)]
struct VerifierRandomnessChallenge {
    player_b: u32,
    player_e: Scalar
}

#[derive(Serialize, Deserialize, Debug)]
struct ProverRandomnessResponse {
    final_commitment: RistrettoPoint,
    z0: Scalar,
    z1: Scalar,
    e0: Scalar,
    e1: Scalar
}

#[derive(Serialize, Deserialize, Debug)]
struct QueryMessage {
    coefficients: HashMap<u16, Scalar>
}

#[derive(Serialize, Deserialize, Debug)]
struct QueryAnswerMessage {
    answer: Scalar,
    proof: Scalar
}

struct ProverState {
    rng: OsRng,
    shared_rng: ChaCha20Rng,
    pedersen_pp: PublicParams,
    monomial_map: HashMap<u16, (Scalar, RistrettoPoint, Scalar)>,
    C0: RistrettoPoint,
    C1: RistrettoPoint,
    CPROOF: Scalar,
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
}

struct VerifierState {
    rng: OsRng,
    shared_rng: ChaCha20Rng,
    pedersen_pp: PublicParams,
    monomial_commitments: HashMap<u16, RistrettoPoint>,
    C0: RistrettoPoint,
    C1: RistrettoPoint,
    CPROOF: Scalar,
    player_b: u32,
    player_e: Scalar,
    randomness_bit_comm: RistrettoPoint,
}

//
// -- SETUP PHASE --
//

// 0
fn prover_setup(prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) -> ProverState {

    let mut rng = OsRng::default();
    let prover_seed = rng.gen::<[u8; 32]>();

    let mut shared_rng = ChaCha20Rng::from_seed(prover_seed);

    let pedersen_pp = setup(&mut shared_rng);

    let CPROOF = Scalar::from(0 as u32);
    let C0 = commit_with_r(&Scalar::from(0 as u32), &CPROOF, &pedersen_pp);
    let C1 = commit_with_r(&Scalar::from(1 as u32), &CPROOF, &pedersen_pp);

    let setup_message = SetupMessage {
        seed: prover_seed
    };
    verifier_mailbox.push_back(
        serde_json::to_string(&setup_message).unwrap()
    );

    ProverState {
        rng: rng,
        shared_rng: shared_rng,
        pedersen_pp: pedersen_pp,
        monomial_map: HashMap::new(),
        C0: C0,
        C1: C1,
        CPROOF: CPROOF,
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

// 1
fn verifier_setup(prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) -> VerifierState {

    let rng = OsRng::default();
   
    let setup_message: SetupMessage = serde_json::from_str(
        &verifier_mailbox.pop_front().unwrap()
    ).unwrap();

    let mut shared_rng = ChaCha20Rng::from_seed(setup_message.seed);

    let pedersen_pp = setup(&mut shared_rng);

    let CPROOF = Scalar::from(0 as u32);
    let C0 = commit_with_r(&Scalar::from(0 as u32), &CPROOF, &pedersen_pp);
    let C1 = commit_with_r(&Scalar::from(1 as u32), &CPROOF, &pedersen_pp);

    VerifierState {
        rng: rng,
        shared_rng: shared_rng,
        pedersen_pp: pedersen_pp,
        monomial_commitments: HashMap::new(),
        C0: C0,
        C1: C1,
        CPROOF: CPROOF,
        player_b: 0,
        player_e: Scalar::default(),
        randomness_bit_comm: RistrettoPoint::default(),
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

fn generate_monomial_sums_helper<T: PrimInt + Hash>(indices: T, current_idx: T, data: &[T], monomial_map: &mut HashMap<T, Scalar>) {

    if current_idx.to_u32().unwrap() == D || indices.count_ones() == K {
        let sum = calculate_monomial_sum(indices, data);
        monomial_map.insert(indices, sum);
        return;
    }

    // set bit at current index to a 0 or 1 and recurse
    generate_monomial_sums_helper(
        indices, current_idx + T::one(), data, monomial_map);
    generate_monomial_sums_helper(
        indices | (T::one() << current_idx.to_usize().unwrap()), current_idx + T::one(), data, monomial_map);
}

fn generate_monomial_sums<T: PrimInt + Hash>(data: &[T]) -> HashMap<T, Scalar> {
    let mut map = HashMap::new();
    generate_monomial_sums_helper(T::zero(), T::zero(), data, &mut map);
    map
}

// 2
fn prover_commitment_phase(state: &mut ProverState,
                           prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) {
    let monomial_map = generate_monomial_sums(&TEST_DATA);

    let mut monomial_commitments = HashMap::new();
    for (monomial_id, monomial_sum) in monomial_map {
        let (comm, proof) = commit(&mut state.rng, &monomial_sum, &state.pedersen_pp);
        state.monomial_map.insert(monomial_id, (monomial_sum, comm, proof));
        monomial_commitments.insert(monomial_id, comm);
    } 

    let m = CommitmentMapMessage {
        commitment_map: monomial_commitments
    };

    verifier_mailbox.push_back(
        serde_json::to_string(&m).unwrap()
    );
}

// 3
fn verifier_commitment_phase(state: &mut VerifierState,
                             prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) {
    
    let m: CommitmentMapMessage = serde_json::from_str(
        &verifier_mailbox.pop_front().unwrap()
    ).unwrap();

    state.monomial_commitments = m.commitment_map;
}

//
// -- RANDOMNESS PHASE --
//

// 4
fn prover_randomness_phase_comm(state: &mut ProverState,
    prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) {

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
    verifier_mailbox.push_back(
        serde_json::to_string(&m).unwrap()
    );

    state.dealer_b = dealer_b;
    state.dealer_b_comm = dealer_b_comm;
    state.dealer_b_proof = dealer_b_proof;
    state.dealer_e = dealer_e;
    state.dealer_sigma_b_comm = dealer_sigma_b_comm;
    state.dealer_sigma_b_proof = dealer_sigma_b_proof;
    state.dealer_sigma_not_b_proof = dealer_sigma_not_b_proof;
}

// 5
fn verifer_randomness_phase_challenge(state: &mut VerifierState,
     prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) {

    // CF 2: PL flips a bit and sends it
    let player_b: u32 = state.rng.gen_range(0..2);

    // SP 2: PL sends a random e value
    let player_e = Scalar::random(&mut state.rng);

    let m: VerifierRandomnessChallenge = VerifierRandomnessChallenge {
        player_b: player_b,
        player_e: player_e
    };
    prover_mailbox.push_back(
        serde_json::to_string(&m).unwrap()
    );

    state.player_b = player_b;
    state.player_e = player_e;
}

// 6
fn prover_randomness_phase_response(state: &mut ProverState, 
    prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) {

    // CF 3
    let final_commitment: RistrettoPoint;
    let final_proof: Scalar;
    let final_b: u32;

    let m: VerifierRandomnessChallenge = serde_json::from_str(
        &prover_mailbox.pop_front().unwrap()
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
    verifier_mailbox.push_back(
        serde_json::to_string(&m).unwrap()
    );

    state.final_b = final_b;
    state.final_proof = final_proof;
}

// 7
fn verifier_randomness_phase_check(state: &mut VerifierState,
    prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) -> Option<RistrettoPoint> {

    let comm_msg: ProverRandomnessComm = serde_json::from_str(
        &verifier_mailbox.pop_front().unwrap()
    ).unwrap();

    let resp_msg: ProverRandomnessResponse = serde_json::from_str(
        &verifier_mailbox.pop_front().unwrap()
    ).unwrap();

    // CF 4
    if state.player_b == 0 {
        if resp_msg.final_commitment != comm_msg.dealer_b_comm {
            println!("ERROR: player_b = 0, final_commitment != dealer_b_comm");
            return None;
        }
    } else {
        if resp_msg.final_commitment != state.C1 + comm_msg.dealer_b_comm.neg() {
            println!("ERROR: player_b = 1, final_commitment != C1 + dealer_b_comm.neg()");
            return None;
        }
    }

    // SP 4
    if state.player_e != resp_msg.e0 + resp_msg.e1 {
        println!("ERROR: player_e != e0 + e1");
        return None;
    }

    let comm_0 = commit_with_r(&Scalar::from(0 as u32), &resp_msg.z0, &state.pedersen_pp);
    if comm_0 != comm_msg.c0 + (resp_msg.e0 * comm_msg.dealer_b_comm) {
        println!("ERROR: comm_0 != c0 + (e0 * dealer_b_comm)");
        return None;
    }

    let comm_1 = commit_with_r(&(Scalar::from(1 as u32) + resp_msg.e1), &resp_msg.z1, &state.pedersen_pp);
    if comm_1 != comm_msg.c1 + (resp_msg.e1 * comm_msg.dealer_b_comm){
        println!("ERROR: comm_1 != c1 + (e1 * dealer_b_comm)");
        return None;
    }

    return Some(resp_msg.final_commitment);
    //return Some((Scalar::from(final_b), final_commitment, final_proof));
}

// 8
fn prover_randomness_phase_adjust(state: &mut ProverState,
                                  prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) {
    let adjustment_factor = Scalar::from((N/2) as u32);
    state.randomness_bit_sum -= adjustment_factor;
    state.randomness_bit_proof -= state.CPROOF;
}

// 9
fn verifier_randomness_phase_adjust(state: &mut VerifierState,
                                    prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) {
    let adjustment_factor = Scalar::from((N/2) as u32);
    state.randomness_bit_comm -= commit_with_r(&adjustment_factor, &state.CPROOF, &state.pedersen_pp);
}

//
// -- QUERYING PHASE --
//

// 10
fn verifier_generate_query(state: &mut VerifierState,
                           prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) -> HashMap<u16, Scalar> {
    
    let mut coefficients: HashMap<u16, Scalar> = HashMap::new();
    for _ in 0..NUM_COEFFICIENTS {
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
fn verifier_send_query(state: &mut VerifierState, query_coefficients: &HashMap<u16, Scalar>,
                       prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) {
    let m = QueryMessage {
        coefficients: query_coefficients.clone()
    };
    prover_mailbox.push_back(
        serde_json::to_string(&m).unwrap()
    );
}

//12
fn prover_answer_query(state: &mut ProverState, prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) {
    let query_m: QueryMessage = serde_json::from_str(
        &prover_mailbox.pop_front().unwrap()
    ).unwrap();

    let mut query_answer = state.randomness_bit_sum;
    let mut query_proof = state.randomness_bit_proof;

    for monomial_id in query_m.coefficients.keys() {
        if !state.monomial_map.contains_key(monomial_id) {
            println!("ERROR: Monomial ID {} not found in monomial map", monomial_id);
            return;
        }

        let (monomial_sum, monomial_comm, monomial_proof) = state.monomial_map.get(monomial_id).unwrap();
        let monomial_coefficient = query_m.coefficients.get(monomial_id).unwrap();

        query_answer += monomial_coefficient * monomial_sum;
        query_proof += monomial_coefficient * monomial_proof;
    }

    verifier_mailbox.push_back(
        serde_json::to_string(&QueryAnswerMessage {
            answer: query_answer,
            proof: query_proof
        }).unwrap()
    );
}

fn verifier_check_query(state: &mut VerifierState, query_coefficients: &HashMap<u16, Scalar>,
                        prover_mailbox: &mut VecDeque<String>, verifier_mailbox: &mut VecDeque<String>) {
    let query_answer_m: QueryAnswerMessage = serde_json::from_str(
        &verifier_mailbox.pop_front().unwrap()
    ).unwrap();

    let mut query_comm = state.randomness_bit_comm;

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

    if verify(&query_comm, &query_proof, &query_answer, &state.pedersen_pp) {
        println!("verified!");
    } else {
        println!("invalid :(");
    }
}

fn main() {

    println!("\n-- Running VDP Protocol --\n");

    let mut prover_mailbox: VecDeque<String> = VecDeque::new();
    let mut verifier_mailbox: VecDeque<String> = VecDeque::new();

    let mut verifier_state: VerifierState;

    // Setup
    print!("Setup phase...");
    io::stdout().flush().unwrap();
    
    let mut prover_state: ProverState = prover_setup(&mut prover_mailbox, &mut verifier_mailbox);
    let mut verifier_state: VerifierState = verifier_setup(&mut prover_mailbox, &mut verifier_mailbox);
    
    println!("complete");

    // Commitment Phase
    print!("Commitment phase...");
    io::stdout().flush().unwrap();
   
    prover_commitment_phase(&mut prover_state, &mut prover_mailbox, &mut verifier_mailbox);
    verifier_commitment_phase(&mut verifier_state, &mut prover_mailbox, &mut verifier_mailbox);
   
    println!("complete");
    
    // Randomness Phase
    print!("Randomness phase...");
    io::stdout().flush().unwrap();

    prover_state.randomness_bit_sum = Scalar::from(0 as u32);
    prover_state.randomness_bit_proof = prover_state.CPROOF;

    verifier_state.randomness_bit_comm = verifier_state.C0;

    for _ in 0..N {
        prover_randomness_phase_comm(&mut prover_state, &mut prover_mailbox, &mut verifier_mailbox);
        verifer_randomness_phase_challenge(&mut verifier_state, &mut prover_mailbox, &mut verifier_mailbox);
        prover_randomness_phase_response(&mut prover_state, &mut prover_mailbox, &mut verifier_mailbox);
        match verifier_randomness_phase_check(&mut verifier_state, &mut prover_mailbox, &mut verifier_mailbox) {
            Some(c) => {
                prover_state.randomness_bit_sum += Scalar::from(prover_state.final_b);
                prover_state.randomness_bit_proof += prover_state.final_proof;
                verifier_state.randomness_bit_comm += c;
            },
            None => {
                println!("ERROR: Randomness phase failed");
                return;
            }
        }
    }
    prover_randomness_phase_adjust(&mut prover_state, &mut prover_mailbox, &mut verifier_mailbox);
    verifier_randomness_phase_adjust(&mut verifier_state, &mut prover_mailbox, &mut verifier_mailbox);

    println!("complete");

    // Query generation
    print!("Query generation...");
    io::stdout().flush().unwrap();

    let query_coefficients = verifier_generate_query(&mut verifier_state, &mut prover_mailbox, &mut verifier_mailbox);
    
    println!("complete");

    // Query phase
    print!("Query phase...");
    io::stdout().flush().unwrap();

    verifier_send_query(&mut verifier_state, &query_coefficients, &mut prover_mailbox, &mut verifier_mailbox);
    prover_answer_query(&mut prover_state, &mut prover_mailbox, &mut verifier_mailbox);
    verifier_check_query(&mut verifier_state, &query_coefficients, &mut prover_mailbox, &mut verifier_mailbox);
    
    println!("");
}
