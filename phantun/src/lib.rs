use std::time::Duration;

pub mod fec;
pub mod proto;
pub mod utils;

pub const UDP_TTL: Duration = Duration::from_secs(180);
