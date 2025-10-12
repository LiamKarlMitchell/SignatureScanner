//! Buffer scanning implementation

use super::{ScanOptions, TargetScanner};
use crate::error::{Result, ScannerError};
use crate::pattern::{match_pattern, PatternByte};

/// Scanner for in-memory buffers
pub struct BufferScanner;

impl BufferScanner {
    pub fn new() -> Self {
        Self
    }

    /// Calculate the final result address based on pattern and options
    pub fn calculate_result_address(
        match_pos: usize,
        pattern: &str,
        data: &[u8],
        options: &ScanOptions,
        parsed_pattern: &[PatternByte],
    ) -> Result<usize> {
        if pattern.contains('X') {
            let x_pos = pattern.find('X').unwrap();
            let x_byte_pos = x_pos / 2;

            if match_pos + x_byte_pos + 4 <= data.len() {
                let addr_bytes = &data[match_pos + x_byte_pos..match_pos + x_byte_pos + 4];
                let addr = u32::from_le_bytes([
                    addr_bytes[0],
                    addr_bytes[1],
                    addr_bytes[2],
                    addr_bytes[3],
                ]) as usize;
                Ok(addr.wrapping_add(options.offset as usize))
            } else {
                Err(ScannerError::MemoryAccess(
                    "Address extraction out of bounds".to_string(),
                ))
            }
        } else if options.from_start {
            Ok(match_pos.wrapping_add(options.offset as usize))
        } else {
            Ok(match_pos + parsed_pattern.len() + options.offset as usize)
        }
    }
}

impl TargetScanner for BufferScanner {
    fn search_pattern(
        &self,
        data: &[u8],
        pattern: &str,
        parsed_pattern: &[PatternByte],
        options: &ScanOptions,
    ) -> Result<Option<usize>> {
        let start = if options.start_address > 0 {
            options.start_address
        } else {
            0
        };
        
        if start >= data.len() {
            return Ok(None);
        }

        for i in start..=(data.len().saturating_sub(parsed_pattern.len())) {
            if match_pattern(&data[i..], parsed_pattern) {
                return Ok(Some(Self::calculate_result_address(
                    i,
                    pattern,
                    data,
                    options,
                    parsed_pattern,
                )?));
            }
        }

        Ok(None)
    }
}

impl Default for BufferScanner {
    fn default() -> Self {
        Self::new()
    }
}