use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use num_traits::{PrimInt, FromBytes, ToBytes};
use rand::{CryptoRng, Fill, Rng};
use std::collections::HashMap;

pub struct Data<T> {
    pub entries: Vec<T>,
    pub commitments: HashMap<T, (Scalar, RistrettoPoint, Scalar)>,
}

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

    // pub fn save_to_file(&self, filename: &str) {
    //     let mut file = File::create(filename).unwrap();
    //     let mut writer = BufWriter::new(&file);

    //     let db_str = 

    //     for entry in &self.entries {
    //         writer.write_all(&entry.to_le_bytes()).unwrap();
    //     }
    // }
}