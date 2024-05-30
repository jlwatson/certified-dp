/**
 * data.rs
 * 
 * Structures for the individual database entries and their commitments, based on configured type (e.g., u16)
 */

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use num_traits::{PrimInt, FromBytes, ToBytes};
use rand::{CryptoRng, Fill, Rng};
use std::collections::HashMap;

/// Database entries and commitments are just a vector of values and hashmap of commitments, respectively
pub struct Data<T> {
    pub entries: Vec<T>,
    pub commitments: HashMap<T, (Scalar, RistrettoPoint, Scalar)>,
}

/// Helper to generate random data and an empty hashmap of commitments for testing
impl<T> Data<T>
where
    T: PrimInt + ToBytes + FromBytes<Bytes = <T as ToBytes>::Bytes>,
    <T as ToBytes>::Bytes: Sized + Fill,
    <T as FromBytes>::Bytes: Sized + Fill
{
    pub fn new<R: Rng + CryptoRng>(rng: &mut R, db_size: u32) -> Self {

        let mut entries = Vec::new();
        let commitments = HashMap::new();

        for _ in 0..db_size {

            let mut val: T = T::zero();
            let mut bytes = val.to_le_bytes();
            rng.fill(&mut bytes);
            val = T::from_le_bytes(&bytes);
            entries.push(val);
        }

        Data {
            entries,
            commitments,
        }
    }
}