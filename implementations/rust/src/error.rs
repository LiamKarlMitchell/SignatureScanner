//! Error types for SignatureScanner
//!
//! This module defines all error types that can occur during scanning operations.

use std::io;
use thiserror::Error;

/// Result type for SignatureScanner operations
pub type Result<T> = std::result::Result<T, ScannerError>;

/// Errors that can occur during scanning operations
#[derive(Error, Debug)]
pub enum ScannerError {
    /// Invalid pattern string provided
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
    
    /// Memory access error during scanning
    #[error("Memory access error: {0}")]
    MemoryAccess(String),
    
    /// File I/O error
    #[error("File I/O error: {0}")]
    FileIo(#[from] io::Error),
    
    /// Windows API error
    #[error("Windows API error: {0}")]
    WindowsApi(String),
}