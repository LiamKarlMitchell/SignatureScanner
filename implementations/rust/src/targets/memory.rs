//! Process memory scanning implementation (Windows only)

use super::ScanOptions;
use crate::error::Result;
use crate::pattern::{match_pattern, PatternByte};
use crate::platform::windows::{
    is_memory_executable, is_memory_readable, query_memory, MemoryProtection,
};
use winapi::um::winnt::MEM_COMMIT;

/// Scanner for process memory regions
pub struct MemoryScanner;

impl MemoryScanner {
    pub fn new() -> Self {
        Self
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

    /// Search within a memory slice for patterns
    fn search_in_slice(
        &self,
        data: &[u8],
        pattern: &str,
        parsed_pattern: &[PatternByte],
    ) -> Result<Option<usize>> {
        for i in 0..=(data.len().saturating_sub(parsed_pattern.len())) {
            if match_pattern(&data[i..], parsed_pattern) {
                if pattern.contains('X') {
                    let x_pos = pattern.find('X').unwrap();
                    let x_byte_pos = x_pos / 2;

                    if i + x_byte_pos + 4 <= data.len() {
                        let addr_bytes = &data[i + x_byte_pos..i + x_byte_pos + 4];
                        let addr = u32::from_le_bytes([
                            addr_bytes[0],
                            addr_bytes[1],
                            addr_bytes[2],
                            addr_bytes[3],
                        ]) as usize;
                        return Ok(Some(addr));
                    }
                } else {
                    return Ok(Some(i));
                }
            }
        }
        Ok(None)
    }
}

impl Default for MemoryScanner {
    fn default() -> Self {
        Self::new()
    }
}