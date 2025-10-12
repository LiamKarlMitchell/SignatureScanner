//! Main Scanner implementation with public API methods

use crate::error::Result;
use crate::pattern::parse_pattern;
use crate::targets::{
    buffer::BufferScanner, file::{FileScanner, MappedFileScanner}, ScanOptions, ScanTarget, TargetScanner
};
use crate::utils::text_to_hex;

#[cfg(windows)]
use crate::{
    platform::windows::ProcessInfo,
    targets::memory::MemoryScanner,
};

/// Main scanner for pattern matching operations
pub struct Scanner {
    #[cfg(windows)]
    process_info: Option<ProcessInfo>,
}

impl Scanner {
    /// Create a new Scanner instance
    /// 
    /// On Windows, this will attempt to get process information for memory scanning.
    /// On other platforms, this always succeeds.
    pub fn new() -> Result<Self> {
        #[cfg(windows)]
        {
            match ProcessInfo::current_process() {
                Ok(process_info) => Ok(Self {
                    process_info: Some(process_info),
                }),
                Err(_) => Ok(Self {
                    process_info: None,
                }),
            }
        }
        #[cfg(not(windows))]
        {
            Ok(Self {})
        }
    }

    /// Search for a pattern in the specified target
    pub fn search(&self, target: &ScanTarget, pattern: &str) -> Result<Option<usize>> {
        self.search_with_options(target, pattern, &ScanOptions::default())
    }

    /// Search with custom options
    pub fn search_with_options(
        &self,
        target: &ScanTarget,
        pattern: &str,
        options: &ScanOptions,
    ) -> Result<Option<usize>> {
        let parsed_pattern = parse_pattern(pattern)?;

        match target {
            ScanTarget::Buffer(data) => {
                let scanner = BufferScanner::new();
                scanner.search_pattern(data, pattern, &parsed_pattern, options)
            }
            ScanTarget::File(path) => {
                let scanner = FileScanner::new();
                scanner.scan_file(path, pattern, &parsed_pattern, options)
            }
            ScanTarget::MappedFile(path) => {
                let scanner = MappedFileScanner::new();
                scanner.scan_mapped_file(path, pattern, &parsed_pattern, options)
            }
            #[cfg(windows)]
            ScanTarget::ProcessMemory {
                base_address,
                size,
                scan_executable_only,
            } => {
                let scanner = MemoryScanner::new();
                scanner.scan_process_memory(
                    *base_address,
                    *size,
                    *scan_executable_only,
                    pattern,
                    &parsed_pattern,
                    options,
                )
            }
        }
    }

    /// Search for text by converting it to hex pattern
    pub fn search_text(&self, target: &ScanTarget, text: &str) -> Result<Option<usize>> {
        let hex_pattern = text_to_hex(text);
        self.search(target, &hex_pattern)
    }

    /// Find all occurrences of a pattern
    pub fn find_all(&self, target: &ScanTarget, pattern: &str) -> Result<Vec<usize>> {
        let mut results = Vec::new();
        let mut options = ScanOptions::default();

        loop {
            match self.search_with_options(target, pattern, &options)? {
                Some(pos) => {
                    results.push(pos);
                    options.start_address = pos + 1;

                    if let Some(max) = options.max_results {
                        if results.len() >= max {
                            break;
                        }
                    }
                }
                None => break,
            }
        }

        Ok(results)
    }

    /// Scan current process memory (Windows only)
    #[cfg(windows)]
    pub fn scan_current_process(
        &self,
        pattern: &str,
        executable_only: bool,
    ) -> Result<Option<usize>> {
        if let Some(ref process_info) = self.process_info {
            let target = ScanTarget::ProcessMemory {
                base_address: process_info.base_address,
                size: process_info.module_size,
                scan_executable_only: executable_only,
            };
            self.search(&target, pattern)
        } else {
            Ok(None)
        }
    }

    /// Find all occurrences in current process memory (Windows only)
    #[cfg(windows)]
    pub fn scan_current_process_all(
        &self,
        pattern: &str,
        executable_only: bool,
    ) -> Result<Vec<usize>> {
        if let Some(ref process_info) = self.process_info {
            let target = ScanTarget::ProcessMemory {
                base_address: process_info.base_address,
                size: process_info.module_size,
                scan_executable_only: executable_only,
            };
            self.find_all(&target, pattern)
        } else {
            Ok(Vec::new())
        }
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| {
            #[cfg(windows)]
            {
                Self {
                    process_info: None,
                }
            }
            #[cfg(not(windows))]
            {
                Self {}
            }
        })
    }
}