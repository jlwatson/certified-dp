
mod pedersen;

use rand::rngs::OsRng;
use pedersen::*;

fn main() {

    let mut rng: OsRng = OsRng::default();
    let pp = setup(&mut rng);

    let val1: Value = Value::random(&mut rng);
    let (comm1, proof1) = commit(&mut rng, &val1, &pp);
    assert_eq!(verify(&comm1, &proof1, &val1, &pp), true);

    let val2: Value = Value::random(&mut rng);
    let (comm2, proof2) = commit(&mut rng, &val2, &pp);
    assert_eq!(verify(&comm2, &proof2, &val2, &pp), true);

    let combined_val = add_value(&val1, &val2);
    let combined_comm = add_comm(&comm1, &comm2);
    let combined_proof = add_proof(&proof1, &proof2);

    assert_eq!(verify(&combined_comm, &combined_proof, &combined_val, &pp), true);

    let a = Value::random(&mut rng);
    let scaled_val = scale_value(&val1, &a);
    let scaled_comm = scale_comm(&comm1, &a);
    let scaled_proof = scale_proof(&proof1, &a);

    assert_eq!(verify(&scaled_comm, &scaled_proof, &scaled_val, &pp), true);

    println!("Done!");
}
