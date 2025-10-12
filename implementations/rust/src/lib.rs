//! # SignatureScanner
//!
//! A powerful, cross-platform signature/pattern scanning library for Rust that supports 
//! memory scanning, file scanning, and advanced pattern matching with wildcards and address extraction.
//!
//! ## Features
//!
//! - **Hex Pattern Matching**: Search for exact byte sequences using hex strings
//! - **Wildcard Support**: Use `??` for single-byte wildcards that match any value  
//! - **Address Extraction**: Use `XXXXXXXX` patterns to extract little-endian addresses
//! - **Text Search**: Convert text to hex and search for string patterns
//! - **Multiple Scanning Targets**: Buffers, files, memory-mapped files, and process memory (Windows)
//! - **Cross-platform**: Works on Windows, Linux, and macOS
//! - **Memory Safety**: Safe Rust implementation with comprehensive error handling
//!
//! ## Quick Start
//!
//! ```rust
//! use signature_scanner_rust::{Scanner, ScanTarget};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let scanner = Scanner::new()?;
//! 
//! // Search in a buffer
//! let data = vec![0x3A, 0xB2, 0xDF, 0xAB, 0xFF, 0xFF];
//! let target = ScanTarget::Buffer(data);
//! 
//! if let Some(position) = scanner.search(&target, "3AB2DFAB")? {
//!     println!("Pattern found at position: {}", position);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Pattern Syntax
//!
//! - `3AB2DFAB` - Exact byte sequence (hex values)
//! - `3A??DFAB` - Wildcard pattern (`??` matches any byte)  
//! - `3AXXXXXXB1` - Address marker (`XX` marks 4-byte address extraction point)
//!
//! ## Scanning Targets
//!
//! ```rust
//! # use signature_scanner_rust::{Scanner, ScanTarget};
//! # let scanner = Scanner::new().unwrap();
//! 
//! // Buffer scanning
//! let target = ScanTarget::Buffer(vec![0x3A, 0xB2, 0xDF, 0xAB]);
//! 
//! // File scanning  
//! let target = ScanTarget::File("binary_file.bin".to_string());
//! 
//! // Memory-mapped file (efficient for large files)
//! let target = ScanTarget::MappedFile("large_file.bin".to_string());
//! 
//! // Process memory (Windows only)
//! #[cfg(windows)]
//! let target = ScanTarget::ProcessMemory {
//!     base_address: 0x400000,
//!     size: 0x100000, 
//!     scan_executable_only: true,
//! };
//! ```

// Re-export main public API
pub use scanner::Scanner;
pub use targets::{ScanTarget, ScanOptions};
pub use error::{ScannerError, Result};
pub use pattern::PatternByte;

// Module declarations
pub mod scanner;
pub mod targets;
pub mod pattern;
pub mod platform;
pub mod error;
pub mod utils;

// Conditional Windows imports for documentation
#[cfg(windows)]
pub use winapi;

#[cfg(windows)]
pub use memmap2;