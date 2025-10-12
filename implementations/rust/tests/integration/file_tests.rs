//! File scanning integration tests

use signature_scanner_rust::{Scanner, ScanTarget, Result};
use std::io::Write;

fn create_test_data() -> Vec<u8> {
    vec![
        0x00, 0x01, 0x02, 0x03,           // Start padding (0-3)
        0x3A, 0xB2, 0xDF, 0xAB,           // Pattern start (4-7)
        0xFF, 0xFF, 0xFF, 0xFF,           // Wildcard area (8-11)
        0x3F, 0xBA, 0xCD, 0x30,           // Pattern middle (12-15)
        0x48, 0x65, 0x6C, 0x6C, 0x6F,     // "Hello" text (16-20)
        0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, // " World" text (21-26)
        0x00, 0x00, 0x00, 0x00,           // End padding (27-30)
    ]
}

#[test]
fn test_file_scanning() -> Result<()> {
    let scanner = Scanner::new()?;
    let test_data = create_test_data();

    // Create a temporary test file
    let temp_file = "test_scan_file.bin";
    {
        let mut file = std::fs::File::create(temp_file)?;
        file.write_all(&test_data)?;
    }

    // Test file scanning
    let target = ScanTarget::File(temp_file.to_string());
    let result = scanner.search(&target, "3AB2DFAB")?;
    assert_eq!(result, Some(4));

    // Test memory-mapped file scanning
    let target = ScanTarget::MappedFile(temp_file.to_string());
    let result = scanner.search(&target, "3AB2DFAB")?;
    assert_eq!(result, Some(4));

    // Test text search in file
    let result = scanner.search_text(&target, "Hello World")?;
    assert_eq!(result, Some(16));

    // Clean up
    std::fs::remove_file(temp_file).ok();

    Ok(())
}

#[test]
fn test_large_file_performance() -> Result<()> {
    let scanner = Scanner::new()?;

    // Create a larger test file
    let temp_file = "large_test_file.bin";
    {
        let mut file = std::fs::File::create(temp_file)?;
        // Write 100KB of data with pattern at the end
        let mut data = vec![0x00; 100000];
        data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        file.write_all(&data)?;
    }

    // Test memory-mapped scanning (should be faster for large files)
    let target = ScanTarget::MappedFile(temp_file.to_string());
    let result = scanner.search(&target, "DEADBEEF")?;
    assert_eq!(result, Some(100000));

    // Clean up
    std::fs::remove_file(temp_file).ok();

    Ok(())
}

#[test]
fn test_file_not_found() {
    let scanner = Scanner::new().unwrap();
    let target = ScanTarget::File("non_existent_file.bin".to_string());
    let result = scanner.search(&target, "3AB2");
    assert!(result.is_err());
}