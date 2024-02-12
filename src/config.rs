// DP parameters
#[inline]
pub fn get_n(db_size: u32, epsilon: f32, delta: Option<f32>) -> u32 {
    match delta {
        Some(d) => ((8.0 * (2.0 / d).log2()) / epsilon.powi(2)).ceil() as u32,
        // Delta set to 1/size^(log(size)), thus N = 8 * log(2/delta) / epsilon^(2)
        None => ((8 * (db_size.ilog2().pow(2) + 1)) as f32 / (epsilon.powi(2) as f32)).ceil() as u32
    }
}

#[inline]
pub fn get_delta(db_size: u32, delta: Option<f32>) -> f32 {
    match delta {
        Some(d) => d,
        None => 1.0 / (db_size as f32).powf(db_size.ilog2() as f32) as f32
    }
}

// Prover configuration
pub const PROVER_ADDRESS: &str = "127.0.0.1";
pub const PROVER_PORT: &str = "10020";

pub type DataT = u32;