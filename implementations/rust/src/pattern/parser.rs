//! Pattern parsing logic for hex strings with wildcards and address markers

use super::types::PatternByte;
use crate::error::{Result, ScannerError};

/// Parses a hex pattern string into a vector of PatternBytes
/// 
/// Supports:
/// - Hex bytes: "3AB2" -> [0x3A, 0xB2]
/// - Wildcards: "3A??" -> [0x3A, Wildcard]
/// - Address markers: "3AXX" -> [0x3A, AddressMarker]
pub fn parse_pattern(pattern: &str) -> Result<Vec<PatternByte>> {
    let pattern = pattern.to_uppercase();
    let pattern_chars: Vec<char> = pattern.chars().collect();

    if pattern_chars.len() % 2 != 0 {
        return Err(ScannerError::InvalidPattern(
            "Pattern length must be even".to_string(),
        ));
    }

    let mut parsed = Vec::new();
    let mut i = 0;

    while i < pattern_chars.len() {
        let first = pattern_chars[i];
        let second = pattern_chars[i + 1];

        match (first, second) {
            ('?', '?') => parsed.push(PatternByte::Wildcard),
            ('X', 'X') => parsed.push(PatternByte::AddressMarker),
            (f, s) if f.is_ascii_hexdigit() && s.is_ascii_hexdigit() => {
                let byte_val = u8::from_str_radix(&format!("{}{}", f, s), 16)
                    .map_err(|_| ScannerError::InvalidPattern(format!("Invalid hex: {}{}", f, s)))?;
                parsed.push(PatternByte::Exact(byte_val));
            }
            _ => {
                return Err(ScannerError::InvalidPattern(format!(
                    "Invalid pattern characters: {}{}",
                    first, second
                )))
            }
        }

        i += 2;
    }

    Ok(parsed)
}

/// Matches a data slice against a parsed pattern
pub fn match_pattern(data: &[u8], pattern: &[PatternByte]) -> bool {
    if data.len() < pattern.len() {
        return false;
    }

    for (i, pattern_byte) in pattern.iter().enumerate() {
        match pattern_byte {
            PatternByte::Exact(expected) => {
                if data[i] != *expected {
                    return false;
                }
            }
            PatternByte::Wildcard | PatternByte::AddressMarker => {
                continue;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_pattern() {
        let pattern = parse_pattern("3AB2DFAB").unwrap();
        assert_eq!(pattern.len(), 4);
        assert_eq!(pattern[0], PatternByte::Exact(0x3A));
        assert_eq!(pattern[1], PatternByte::Exact(0xB2));
    }

    #[test]
    fn test_parse_wildcard_pattern() {
        let pattern = parse_pattern("3A??DFAB").unwrap();
        assert_eq!(pattern.len(), 4);
        assert_eq!(pattern[0], PatternByte::Exact(0x3A));
        assert_eq!(pattern[1], PatternByte::Wildcard);
    }

    #[test]
    fn test_parse_address_marker() {
        let pattern = parse_pattern("3AXXXXXXB1").unwrap();
        assert_eq!(pattern.len(), 5);
        assert_eq!(pattern[1], PatternByte::AddressMarker);
    }

    #[test]
    fn test_invalid_pattern_odd_length() {
        assert!(parse_pattern("3AB").is_err());
    }

    #[test]
    fn test_invalid_hex_characters() {
        assert!(parse_pattern("3AGZ").is_err());
    }

    #[test]
    fn test_match_pattern() {
        let data = vec![0x3A, 0xB2, 0xDF, 0xAB];
        let pattern = vec![
            PatternByte::Exact(0x3A),
            PatternByte::Wildcard,
            PatternByte::Exact(0xDF),
            PatternByte::Exact(0xAB),
        ];
        
        assert!(match_pattern(&data, &pattern));
        
        let bad_pattern = vec![
            PatternByte::Exact(0x3A),
            PatternByte::Exact(0xFF), // Wrong byte
            PatternByte::Exact(0xDF),
        ];
        
        assert!(!match_pattern(&data, &bad_pattern));
    }
}