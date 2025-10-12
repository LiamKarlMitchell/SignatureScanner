//! Utility functions for SignatureScanner

/// Converts text to uppercase hex string
/// 
/// # Examples
/// ```
/// use signature_scanner_rust::utils::text_to_hex;
/// 
/// assert_eq!(text_to_hex("Hello"), "48656C6C6F");
/// assert_eq!(text_to_hex("A"), "41");
/// ```
pub fn text_to_hex(text: &str) -> String {
    text.bytes()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join("")
}