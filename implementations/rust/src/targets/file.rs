//! File scanning implementations

use super::{buffer::BufferScanner, ScanOptions, TargetScanner};
use crate::error::Result;
use crate::pattern::PatternByte;
use memmap2::Mmap;
use std::fs::File;
use std::io::Read;

/// Scanner for files using direct file I/O
pub struct FileScanner;

impl FileScanner {
    pub fn new() -> Self {
        Self
    }

    /// Scan a file by reading it into memory
    pub fn scan_file(
        &self,
        path: &str,
        pattern: &str,
        parsed_pattern: &[PatternByte],
        options: &ScanOptions,
    ) -> Result<Option<usize>> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let buffer_scanner = BufferScanner::new();
        buffer_scanner.search_pattern(&buffer, pattern, parsed_pattern, options)
    }
}

impl Default for FileScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Scanner for memory-mapped files (more efficient for large files)
pub struct MappedFileScanner;

impl MappedFileScanner {
    pub fn new() -> Self {
        Self
    }

    /// Scan a memory-mapped file
    pub fn scan_mapped_file(
        &self,
        path: &str,
        pattern: &str,
        parsed_pattern: &[PatternByte],
        options: &ScanOptions,
    ) -> Result<Option<usize>> {
        let file = File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        let buffer_scanner = BufferScanner::new();
        buffer_scanner.search_pattern(&mmap[..], pattern, parsed_pattern, options)
    }
}

impl Default for MappedFileScanner {
    fn default() -> Self {
        Self::new()
    }
}