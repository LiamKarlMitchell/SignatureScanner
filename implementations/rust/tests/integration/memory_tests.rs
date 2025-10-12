//! Process memory scanning integration tests (Windows only)

use signature_scanner_rust::{Scanner, Result};

#[test]
fn test_process_memory_scanning() -> Result<()> {
    let scanner = Scanner::new()?;

    // Test scanning current process for a known pattern
    // This is a basic test - in practice you'd scan for specific patterns
    let result = scanner.scan_current_process("90909090", false); // NOP sled
    // We can't assert a specific result since we don't know what's in memory,
    // but we can verify the function doesn't crash
    assert!(result.is_ok());

    // Test executable-only scanning
    let result = scanner.scan_current_process("90909090", true);
    assert!(result.is_ok());

    Ok(())
}

#[test]
fn test_process_memory_all() -> Result<()> {
    let scanner = Scanner::new()?;

    // Test finding all occurrences (likely to find multiple NOPs)
    let results = scanner.scan_current_process_all("90", false)?;
    // Just verify it returns a vector
    let _count = results.len();

    Ok(())
}

#[test]
fn test_executable_only_scanning() -> Result<()> {
    let scanner = Scanner::new()?;

    // Test scanning only executable sections
    let result = scanner.scan_current_process("4D5A", true); // MZ header
    // MZ header should be found in executable sections
    match result? {
        Some(_addr) => {
            // Found MZ header, which is expected
        }
        None => {
            // Might not find it depending on the executable
        }
    }

    Ok(())
}