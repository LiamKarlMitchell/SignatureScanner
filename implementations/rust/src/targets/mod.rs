//! Scanning target implementations
//!
//! This module provides different types of targets that can be scanned for patterns.

pub mod buffer;
pub mod file;
#[cfg(windows)]
pub mod memory;

use crate::error::Result;
use crate::pattern::PatternByte;

/// Configuration options for scanning operations
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Offset to add to the result position
    pub offset: i16,
    /// Whether to return the start position (true) or end position (false)
    pub from_start: bool,
    /// Address to start searching from
    pub start_address: usize,
    /// Maximum number of results for find_all operations
    pub max_results: Option<usize>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            offset: 0,
            from_start: true,
            start_address: 0,
            max_results: None,
        }
    }
}

/// Represents different types of targets that can be scanned
#[derive(Debug, Clone)]
pub enum ScanTarget {
    /// In-memory buffer
    Buffer(Vec<u8>),
    /// File path for direct file scanning
    File(String),
    /// File path for memory-mapped file scanning
    MappedFile(String),
    /// Process memory region (Windows only)
    #[cfg(windows)]
    ProcessMemory {
        base_address: usize,
        size: usize,
        scan_executable_only: bool,
    },
}

/// Trait for scanning implementations
pub trait TargetScanner {
    /// Search for a pattern in the target
    fn search_pattern(
        &self,
        data: &[u8],
        pattern: &str,
        parsed_pattern: &[PatternByte],
        options: &ScanOptions,
    ) -> Result<Option<usize>>;
}