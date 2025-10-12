//! Pattern byte types and related structures

/// Represents a single byte in a parsed pattern
#[derive(Debug, Clone, PartialEq)]
pub enum PatternByte {
    /// Exact byte value to match
    Exact(u8),
    /// Wildcard that matches any byte value
    Wildcard,
    /// Address marker for extracting addresses
    AddressMarker,
}