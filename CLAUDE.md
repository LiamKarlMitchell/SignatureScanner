# Project Overview

SignatureScanner is a cross-platform signature/pattern scanning library for finding patterns in memory or data buffers using hex signatures with wildcards. This monorepo contains implementations in C++, Node.js, and Rust.

# Repository Structure

This is a monorepo with three language implementations:

- `implementations/cpp/` - Original C++ implementation (Windows/Visual Studio)
- `implementations/nodejs/` - JavaScript/Node.js port for buffer scanning
- `implementations/rust/` - Rust implementation (planned/stub)

# Build Commands

## C++ Implementation

```bash
# Open Visual Studio solution
start implementations/cpp/SignatureScanner.sln
```

**Note**: Missing `stdafx.h` file - needs to be created for compilation. Uses Visual Studio 2008 format.

## Node.js Implementation

```bash
cd implementations/nodejs
npm install
npm test  # Note: test.js file doesn't exist yet
```

## Rust Implementation

```bash
cd implementations/rust
cargo build
cargo test
```

**Note**: Currently only stub implementation - needs full development.

# Core Architecture

## Pattern Syntax

- `?` = Single byte wildcard (matches any byte)
- `XXXXXXXX` = 4-byte address marker (extracts address at this position)
- Hex strings = Exact byte matches (e.g., `3AB2DFAB`)

## Key Algorithms

**C++ Implementation** (`implementations/cpp/SignatureScanner.cpp`):

- Memory protection management with `VirtualProtect`
- Process memory scanning with wildcard pattern matching
- Address extraction for `XXXXXXXX` patterns
- `find_all()` method for multiple matches

**Node.js Implementation** (`implementations/nodejs/SigScanner.js`):

- Buffer-based scanning with encoding support (UTF-8, UTF-16LE)
- Streaming results via callbacks
- Configurable search parameters (start/end positions, limits)

## API Patterns

C++ usage:

```cpp
signature_scanner* sig = new signature_scanner();
DWORD_PTR address = sig->search("3AB2DFAB????????3FBACD300200A1XXXXXXXXB1C4DA");
DWORD_PTR text_addr = sig->search_text("Hello World");
```

Node.js usage:

```javascript
const scanner = require("./SigScanner");
const result = scanner.scan(buffer, {
  string: "Hello World",
  encoding: "utf8",
});
```

# Development Notes

## Known Issues

- C++ implementation missing `stdafx.h` dependency
- Node.js test command references non-existent `test.js`
- Rust implementation is placeholder only
- No CI/CD or automated testing configured
- cpp version could be extended for x64 support
- could have a quicker search implemented?
- could search only .code or read-only sections of memory?

## When Adding New Implementations

Follow the established pattern:

1. Create `implementations/{language}/` directory
2. Add language-specific README.md
3. Include build configuration (package.json, Cargo.toml, etc.)
4. Implement core `search()` and `search_text()` functions
5. Support wildcard patterns and address extraction
