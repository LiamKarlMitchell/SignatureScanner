# SignatureScanner Rust Implementation

A powerful, cross-platform signature/pattern scanning library for Rust that supports memory scanning, file scanning, and advanced pattern matching with wildcards and address extraction.

> **✅ RESTRUCTURED**: This library has been completely restructured into a modular, professional architecture suitable for production use and AI-assisted development.

## Features

### Core Capabilities
- ✅ **Hex Pattern Matching**: Search for exact byte sequences using hex strings
- ✅ **Wildcard Support**: Use `??` for single-byte wildcards that match any value
- ✅ **Address Extraction**: Use `XXXXXXXX` patterns to extract little-endian addresses
- ✅ **Text Search**: Convert text to hex and search for string patterns
- ✅ **Multiple Matches**: Find all occurrences of a pattern with `find_all()`

### Scanning Targets
- ✅ **Buffer Scanning**: Search in-memory byte arrays
- ✅ **File Scanning**: Search files directly or with memory mapping
- ✅ **Process Memory Scanning** (Windows): Scan current process memory with protection handling
- ✅ **Stream-like Scanning**: Search data in chunks

### Advanced Features
- ✅ **Memory Protection Management**: Automatic `VirtualProtect` handling on Windows
- ✅ **Executable Section Filtering**: Option to scan only code sections
- ✅ **Cross-platform**: Works on Windows, Linux, and macOS
- ✅ **Error Handling**: Comprehensive error types with detailed messages
- ✅ **Safe Memory Access**: Memory-safe implementation with bounds checking

## Quick Start

```rust
use signature_scanner_rust::{Scanner, ScanTarget};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::new()?;
    
    // Search in a buffer
    let data = vec![0x3A, 0xB2, 0xDF, 0xAB, 0xFF, 0xFF];
    let target = ScanTarget::Buffer(data);
    
    if let Some(position) = scanner.search(&target, "3AB2DFAB")? {
        println!("Pattern found at position: {}", position);
    }
    
    Ok(())
}
```

## Pattern Syntax

- `3AB2DFAB` - Exact byte sequence (hex values)
- `3A??DFAB` - Wildcard pattern (`??` matches any byte)
- `3AXXXXXXB1` - Address marker (`XX` marks 4-byte address extraction point)

## Key API Methods

```rust
// Basic search
let pos = scanner.search(&target, "3AB2DFAB")?;

// Text search
let pos = scanner.search_text(&target, "Hello World")?;

// Find all occurrences
let positions = scanner.find_all(&target, "AABB")?;

// Windows memory scanning
#[cfg(windows)]
let addr = scanner.scan_current_process("90909090", true)?; // executable only
```

## Scanning Targets

```rust
// Buffer scanning
let target = ScanTarget::Buffer(vec![0x3A, 0xB2, 0xDF, 0xAB]);

// File scanning
let target = ScanTarget::File("binary_file.bin".to_string());

// Memory-mapped file (efficient for large files)
let target = ScanTarget::MappedFile("large_file.bin".to_string());

// Process memory (Windows only)
let target = ScanTarget::ProcessMemory {
    base_address: 0x400000,
    size: 0x100000,
    scan_executable_only: true,
};
```

## Use Cases

### 1. DLL Injection / Runtime Scanning
```rust
// When injected into a process
#[cfg(windows)]
let scanner = Scanner::new()?;
let hook_point = scanner.scan_current_process("FF25????????", true)?;
```

### 2. File Analysis
```rust
// Scan PE file for patterns
let file_target = ScanTarget::MappedFile("binary.exe".to_string());
let pe_header = scanner.search(&file_target, "4D5A")?; // MZ header
```

### 3. Address Extraction
```rust
// Extract call targets
let call_pattern = "E8XXXXXXXXC3"; // CALL [addr] RET
if let Some(target_addr) = scanner.search(&target, call_pattern)? {
    println!("Call target: 0x{:X}", target_addr);
}
```

## Platform Support

| Platform | Buffer | File | Memory Mapping | Process Memory |
|----------|--------|------|----------------|----------------|
| Windows  | ✅     | ✅   | ✅             | ✅             |
| Linux    | ✅     | ✅   | ✅             | ❌             |
| macOS    | ✅     | ✅   | ✅             | ❌             |

## Project Structure

The library is organized into focused, modular components:

```
src/
├── lib.rs                 # Public API exports (~80 lines)
├── scanner.rs             # Main Scanner struct (~170 lines)
├── pattern/               # Pattern parsing logic
│   ├── mod.rs            # Module exports
│   ├── parser.rs         # Pattern parsing (~130 lines)
│   └── types.rs          # PatternByte enum
├── targets/               # Scanning implementations
│   ├── mod.rs            # ScanTarget enum and options
│   ├── buffer.rs         # Buffer scanning (~90 lines)
│   ├── file.rs           # File scanning implementations
│   └── memory.rs         # Windows memory scanning
├── platform/             # Platform-specific code
│   ├── mod.rs            
│   └── windows.rs        # Windows API abstractions
├── error.rs              # Error types and handling
└── utils.rs              # Helper functions

tests/integration/        # Focused integration tests
examples/                 # Usage examples
```

### Benefits of This Structure

- **🤖 AI-Friendly**: Each module has clear responsibility, easier for AI to understand
- **🔧 Maintainable**: Changes are isolated to relevant modules
- **📚 Professional**: Follows Rust library best practices
- **🧪 Testable**: Comprehensive test coverage with organized test suites
- **🚀 Extensible**: Easy to add new platforms and scanning targets

## Building

```bash
cargo test    # Run all tests (unit + integration)
cargo test --lib    # Run unit tests only
cargo build --release   # Build optimized version
cargo run --example usage   # Run example
```
