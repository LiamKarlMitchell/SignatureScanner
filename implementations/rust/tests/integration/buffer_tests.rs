//! Buffer scanning integration tests

use signature_scanner_rust::{Scanner, ScanTarget, ScanOptions, Result};

fn create_test_data() -> Vec<u8> {
    vec![
        0x00, 0x01, 0x02, 0x03,           // Start padding (0-3)
        0x3A, 0xB2, 0xDF, 0xAB,           // Pattern start (4-7)
        0xFF, 0xFF, 0xFF, 0xFF,           // Wildcard area (8-11)
        0x3F, 0xBA, 0xCD, 0x30,           // Pattern middle (12-15)
        0x02, 0x00, 0xA1, 0x00,           // Pattern before address (16-19)
        0x78, 0x56, 0x34, 0x12,           // Address bytes (20-23) = 0x12345678 in little endian
        0xB1, 0xC4, 0xDA, 0x00,           // Pattern end (24-27)
        0x48, 0x65, 0x6C, 0x6C, 0x6F,     // "Hello" text (28-32)
        0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, // " World" text (33-38)
        0x00, 0x00, 0x00, 0x00,           // End padding (39-42)
    ]
}

#[test]
fn test_basic_pattern_search() -> Result<()> {
    let scanner = Scanner::new()?;
    let data = create_test_data();
    let target = ScanTarget::Buffer(data);

    // Basic pattern search
    let result = scanner.search(&target, "3AB2DFAB")?;
    assert_eq!(result, Some(4));

    // Pattern with wildcards
    let result = scanner.search(&target, "3AB2DFAB????????3FBACD30")?;
    assert_eq!(result, Some(4));

    // Non-existent pattern
    let result = scanner.search(&target, "DEADBEEF")?;
    assert_eq!(result, None);

    Ok(())
}

#[test]
fn test_address_extraction() -> Result<()> {
    let scanner = Scanner::new()?;
    let data = create_test_data();
    let target = ScanTarget::Buffer(data);

    // Pattern with address marker should extract the address value
    let result = scanner.search(&target, "3AB2DFAB????????3FBACD300200A100XXXXXXXXB1C4DA")?;
    assert_eq!(result, Some(0x12345678));

    // Test with offset
    let options = ScanOptions {
        offset: 10,
        ..Default::default()
    };
    let result = scanner.search_with_options(&target, "3AB2DFAB????????3FBACD300200A100XXXXXXXXB1C4DA", &options)?;
    assert_eq!(result, Some(0x12345678 + 10));

    Ok(())
}

#[test]
fn test_text_search() -> Result<()> {
    let scanner = Scanner::new()?;
    let data = create_test_data();
    let target = ScanTarget::Buffer(data);

    // Search for "Hello" text
    let result = scanner.search_text(&target, "Hello")?;
    assert_eq!(result, Some(28));

    // Search for "World" text
    let result = scanner.search_text(&target, "World")?;
    assert_eq!(result, Some(34));

    // Search for full "Hello World" text
    let result = scanner.search_text(&target, "Hello World")?;
    assert_eq!(result, Some(28));

    Ok(())
}

#[test]
fn test_find_all() -> Result<()> {
    let scanner = Scanner::new()?;

    // Create data with multiple occurrences
    let mut data = vec![0x00, 0x01, 0x02];
    data.extend_from_slice(&[0xAA, 0xBB]); // First occurrence at index 3
    data.extend_from_slice(&[0x03, 0x04, 0x05]);
    data.extend_from_slice(&[0xAA, 0xBB]); // Second occurrence at index 8
    data.extend_from_slice(&[0x06, 0x07]);
    data.extend_from_slice(&[0xAA, 0xBB]); // Third occurrence at index 12

    let target = ScanTarget::Buffer(data);
    let results = scanner.find_all(&target, "AABB")?;
    assert_eq!(results, vec![3, 8, 12]);

    Ok(())
}

#[test]
fn test_scan_options() -> Result<()> {
    let scanner = Scanner::new()?;
    let data = create_test_data();
    let target = ScanTarget::Buffer(data);

    // Test from_start = true (default)
    let options = ScanOptions {
        from_start: true,
        ..Default::default()
    };
    let result = scanner.search_with_options(&target, "3AB2DFAB", &options)?;
    assert_eq!(result, Some(4));

    // Test from_start = false
    let options = ScanOptions {
        from_start: false,
        ..Default::default()
    };
    let result = scanner.search_with_options(&target, "3AB2DFAB", &options)?;
    assert_eq!(result, Some(8)); // start + pattern length

    // Test with start_address
    let options = ScanOptions {
        start_address: 20,
        ..Default::default()
    };
    let result = scanner.search_with_options(&target, "48656C6C6F", &options)?; // "Hello" hex
    assert_eq!(result, Some(28));

    Ok(())
}