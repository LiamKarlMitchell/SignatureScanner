//! Pattern parsing and matching functionality

pub mod types;
pub mod parser;

pub use types::PatternByte;
pub use parser::{parse_pattern, match_pattern};