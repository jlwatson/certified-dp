// DP parameters
#[inline]
pub fn get_n(db_size: u32, epsilon: f32) -> u32 {
    // Delta set to 1/size^(log(size)), thus N = 8 * log(2/delta) / epsilon^(2)
    ((8 * (db_size.ilog2().pow(2) + 1)) as f32 / (epsilon.powi(2) as f32)).ceil() as u32
}

// Prover configuration
pub const PROVER_ADDRESS: &str = "127.0.0.1";
pub const PROVER_PORT: &str = "10020";
