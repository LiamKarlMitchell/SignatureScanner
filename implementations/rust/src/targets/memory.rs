//! Process memory scanning implementation (Windows only)

use super::ScanOptions;
use crate::error::Result;
use crate::pattern::{match_pattern, PatternByte};
use crate::platform::windows::{
    is_memory_executable, is_memory_readable, query_memory, MemoryProtection,
};
use winapi::um::winnt::MEM_COMMIT;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// Scanner for process memory regions
pub struct MemoryScanner;

impl MemoryScanner {
    pub fn new() -> Self {
        Self
    }

    /// Build Boyer-Moore-Horspool bad character table
    fn build_bad_char_table(pattern: &[PatternByte]) -> [usize; 256] {
        let mut table = [pattern.len(); 256];

        // For each position except the last, record the distance to the end
        for (i, pattern_byte) in pattern.iter().enumerate().take(pattern.len().saturating_sub(1)) {
            if let PatternByte::Exact(byte) = pattern_byte {
                table[*byte as usize] = pattern.len() - 1 - i;
            }
        }

        table
    }

    /// Find candidates for the first exact byte using SIMD (x86_64 only)
    /// Returns an iterator-like approach to avoid large allocations
    #[cfg(target_arch = "x86_64")]
    fn find_first_byte_simd(data: &[u8], first_byte: u8) -> Vec<usize> {
        let len = data.len();

        if len < 16 || !is_x86_feature_detected!("sse2") {
            // Fallback for small data or when SSE2 is not available
            return data.iter()
                .enumerate()
                .filter_map(|(i, &byte)| if byte == first_byte { Some(i) } else { None })
                .collect();
        }

        // Pre-allocate with reasonable capacity to avoid many reallocations
        let mut positions = Vec::with_capacity(std::cmp::min(len / 256, 1024));

        unsafe {
            let needle = _mm_set1_epi8(first_byte as i8);
            let mut i = 0;

            // Process 16 bytes at a time using SSE2
            while i + 16 <= len {
                // Use loadu for unaligned access (safe for any memory alignment)
                let ptr = data.as_ptr().add(i);
                let haystack = _mm_loadu_si128(ptr as *const __m128i);
                let cmp = _mm_cmpeq_epi8(haystack, needle);
                let mask = _mm_movemask_epi8(cmp) as u16;

                if mask != 0 {
                    // Found matches, extract positions
                    for bit in 0..16 {
                        if (mask & (1 << bit)) != 0 {
                            positions.push(i + bit);
                        }
                    }
                }

                i += 16;
            }

            // Handle remaining bytes
            for j in i..len {
                if data[j] == first_byte {
                    positions.push(j);
                }
            }
        }

        positions
    }

    /// Fallback implementation for non-x86_64 architectures
    #[cfg(not(target_arch = "x86_64"))]
    fn find_first_byte_simd(data: &[u8], first_byte: u8) -> Vec<usize> {
        data.iter()
            .enumerate()
            .filter_map(|(i, &byte)| if byte == first_byte { Some(i) } else { None })
            .collect()
    }

    /// Scan a memory region of the current process
    pub fn scan_process_memory(
        &self,
        start_addr: usize,
        size: usize,
        executable_only: bool,
        pattern: &str,
        parsed_pattern: &[PatternByte],
        _options: &ScanOptions,
    ) -> Result<Option<usize>> {
        let mut current_addr = start_addr;
        let end_addr = start_addr + size;

        while current_addr < end_addr {
            let mem_info = match query_memory(current_addr) {
                Ok(info) => info,
                Err(_) => {
                    current_addr += 0x1000; // Page size
                    continue;
                }
            };

            // Check if memory is committed
            if mem_info.State != MEM_COMMIT {
                current_addr += mem_info.RegionSize;
                continue;
            }

            // Filter by executable sections if requested
            if executable_only {
                if !is_memory_executable(mem_info.Protect) {
                    current_addr += mem_info.RegionSize;
                    continue;
                }
            } else {
                // Check if memory is readable
                if !is_memory_readable(mem_info.Protect) {
                    current_addr += mem_info.RegionSize;
                    continue;
                }
            }

            // Set memory protection to ensure we can read it
            let _protection = MemoryProtection::new(mem_info.BaseAddress, mem_info.RegionSize).ok();

            // Create a safe slice from the memory region
            let memory_slice = unsafe {
                std::slice::from_raw_parts(
                    current_addr as *const u8,
                    mem_info.RegionSize.min(end_addr - current_addr),
                )
            };

            // Search in this memory region
            if let Some(offset) = self.search_in_slice(memory_slice, pattern, parsed_pattern)? {
                return Ok(Some(current_addr + offset));
            }

            current_addr += mem_info.RegionSize;
        }

        Ok(None)
    }

    /// Optimized search using Boyer-Moore-Horspool + SIMD
    fn search_in_slice_optimized(
        &self,
        data: &[u8],
        pattern: &str,
        parsed_pattern: &[PatternByte],
    ) -> Result<Option<usize>> {
        if data.len() < parsed_pattern.len() {
            return Ok(None);
        }

        let pattern_len = parsed_pattern.len();

        // Check if pattern starts with an exact byte
        let first_exact_at_start = if let Some(PatternByte::Exact(byte)) = parsed_pattern.first() {
            Some(*byte)
        } else {
            None
        };

        // Strategy 1: If pattern starts with exact byte, use SIMD
        // We don't need BMH here because SIMD already gives us all candidate positions
        if let Some(first_byte) = first_exact_at_start {
            let candidates = Self::find_first_byte_simd(data, first_byte);

            for &candidate_pos in &candidates {
                // Bounds check
                if candidate_pos + pattern_len > data.len() {
                    continue;
                }

                // Check if full pattern matches at this position
                if match_pattern(&data[candidate_pos..], parsed_pattern) {
                    return self.handle_match(data, pattern, parsed_pattern, candidate_pos);
                }
            }
        } else {
            // Strategy 2: Pattern starts with wildcards, use BMH with skip optimization
            let bad_char_table = Self::build_bad_char_table(parsed_pattern);
            let mut i = 0;

            while i <= data.len().saturating_sub(pattern_len) {
                if match_pattern(&data[i..], parsed_pattern) {
                    return self.handle_match(data, pattern, parsed_pattern, i);
                }

                // Use BMH bad character table to skip ahead
                // Look at the character at position pattern_len-1 in data
                if i + pattern_len <= data.len() {
                    let skip_char = data[i + pattern_len - 1];
                    i += bad_char_table[skip_char as usize];
                } else {
                    i += 1;
                }
            }
        }

        Ok(None)
    }

    /// Handle pattern match and extract address if needed
    fn handle_match(
        &self,
        data: &[u8],
        pattern: &str,
        _parsed_pattern: &[PatternByte],
        match_pos: usize,
    ) -> Result<Option<usize>> {
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
                return Ok(Some(addr));
            }
        } else {
            return Ok(Some(match_pos));
        }

        Ok(None)
    }

    /// Search within a memory slice for patterns (legacy method kept for compatibility)
    fn search_in_slice(
        &self,
        data: &[u8],
        pattern: &str,
        parsed_pattern: &[PatternByte],
    ) -> Result<Option<usize>> {
        // Delegate to optimized version
        self.search_in_slice_optimized(data, pattern, parsed_pattern)
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}