use signature_scanner_rust::{Scanner, ScanTarget, ScanOptions, Result};

fn main() -> Result<()> {
    // Create a new scanner instance
    let scanner = Scanner::new()?;
    
    println!("=== SignatureScanner Rust Implementation Demo ===\n");
    
    // Example 1: Buffer scanning
    println!("1. Buffer Scanning:");
    let test_data = vec![
        0x00, 0x01, 0x02, 0x03,           // Padding
        0x3A, 0xB2, 0xDF, 0xAB,           // Target pattern
        0xFF, 0xFF, 0xFF, 0xFF,           // Wildcards
        0x3F, 0xBA, 0xCD, 0x30,           // More pattern
        0x48, 0x65, 0x6C, 0x6C, 0x6F,     // "Hello"
        0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, // " World"
    ];
    
    let buffer_target = ScanTarget::Buffer(test_data.clone());
    
    // Basic pattern search
    if let Some(pos) = scanner.search(&buffer_target, "3AB2DFAB")? {
        println!("  Found pattern at position: {}", pos);
    }
    
    // Wildcard search
    if let Some(pos) = scanner.search(&buffer_target, "3AB2DFAB????????3FBACD30")? {
        println!("  Found wildcard pattern at position: {}", pos);
    }
    
    // Text search
    if let Some(pos) = scanner.search_text(&buffer_target, "Hello World")? {
        println!("  Found text 'Hello World' at position: {}", pos);
    }
    
    // Example 2: File scanning
    println!("\n2. File Scanning:");
    
    // Create a test file
    std::fs::write("test_file.bin", &test_data)?;
    
    let file_target = ScanTarget::File("test_file.bin".to_string());
    if let Some(pos) = scanner.search(&file_target, "3AB2DFAB")? {
        println!("  Found pattern in file at position: {}", pos);
    }
    
    // Memory-mapped file scanning (more efficient for large files)
    let mmap_target = ScanTarget::MappedFile("test_file.bin".to_string());
    if let Some(pos) = scanner.search(&mmap_target, "3AB2DFAB")? {
        println!("  Found pattern in memory-mapped file at position: {}", pos);
    }
    
    // Clean up
    std::fs::remove_file("test_file.bin").ok();
    
    // Example 3: Advanced search options
    println!("\n3. Advanced Search Options:");
    
    let options = ScanOptions {
        offset: 10,           // Add offset to result
        from_start: false,    // Return end position instead of start
        start_address: 5,     // Start searching from byte 5
        max_results: Some(5), // Limit results for find_all
    };
    
    if let Some(pos) = scanner.search_with_options(&buffer_target, "3AB2DFAB", &options)? {
        println!("  Pattern found with custom options at: {}", pos);
    }
    
    // Example 4: Find all occurrences
    println!("\n4. Find All Occurrences:");
    
    let multi_data = vec![
        0xAA, 0xBB, 0x00, 0x01,
        0xAA, 0xBB, 0x02, 0x03,
        0xAA, 0xBB, 0x04, 0x05,
    ];
    
    let multi_target = ScanTarget::Buffer(multi_data);
    let results = scanner.find_all(&multi_target, "AABB")?;
    println!("  Found pattern at positions: {:?}", results);
    
    // Example 5: Process memory scanning (Windows only)
    #[cfg(windows)]
    {
        println!("\n5. Process Memory Scanning (Windows):");
        
        // Scan current process memory for a common pattern
        match scanner.scan_current_process("90909090", false) {
            Ok(Some(addr)) => println!("  Found NOP sled at address: 0x{:X}", addr),
            Ok(None) => println!("  No NOP sled found in process memory"),
            Err(e) => println!("  Memory scan error: {}", e),
        }
        
        // Scan only executable sections
        match scanner.scan_current_process("4D5A", true) {
            Ok(Some(addr)) => println!("  Found MZ header in executable section at: 0x{:X}", addr),
            Ok(None) => println!("  No MZ header found in executable sections"),
            Err(e) => println!("  Executable scan error: {}", e),
        }
    }
    
    // Example 6: Address extraction with XXXXXXXX pattern
    println!("\n6. Address Extraction:");
    
    let addr_data = vec![
        0x3A, 0xB2, 0xDF, 0xAB,           // Pattern
        0xFF, 0xFF, 0xFF, 0xFF,           // Wildcards
        0x3F, 0xBA, 0xCD, 0x30,           // More pattern
        0x78, 0x56, 0x34, 0x12,           // Address (0x12345678 little endian)
        0xB1, 0xC4, 0xDA, 0x00,           // End pattern
    ];
    
    let addr_target = ScanTarget::Buffer(addr_data);
    
    // Extract address from pattern
    if let Some(extracted_addr) = scanner.search(&addr_target, "3AB2DFAB????????3FBACD30XXXXXXXXB1C4DA")? {
        println!("  Extracted address: 0x{:X}", extracted_addr);
        println!("  This should be: 0x12345678");
    }
    
    println!("\n=== Demo Complete ===");
    
    Ok(())
}