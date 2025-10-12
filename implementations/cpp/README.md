# C++ Signature Scanner

Original C++ implementation of the Signature Scanner library.

## Building

Open `SignatureScanner.sln` in Visual Studio and build the project.

## Recent Improvements (2024)

The C++ implementation has been modernized with significant improvements:

### Platform Compatibility
- **64-bit Support**: All pointer and address types updated from `unsigned long` to `uintptr_t` for proper 32/64-bit compatibility
- **Memory Size Handling**: Uses `SIZE_T` for memory operations to prevent truncation on 64-bit systems
- **Cross-Platform Types**: Eliminates platform-specific size assumptions

### Security & Safety
- **Buffer Safety**: Replaced unsafe `sprintf` with `sprintf_s` to prevent buffer overflows
- **Proper Bounds Checking**: Added buffer size validation in string formatting operations
- **Memory Protection**: Fixed VirtualProtect parameter handling to prevent NULL pointer issues

### Code Quality
- **Type Safety**: Eliminated implicit type conversions that could cause data loss
- **Modern C++ Types**: Uses `size_t` for string lengths and loop counters
- **Compiler Warnings**: Resolved all MSVC compilation warnings and errors
- **Logic Fixes**: Corrected logical vs bitwise operator usage

### API Improvements
- **Return Types**: Functions now return `uintptr_t` instead of `unsigned long` for addresses
- **Vector Support**: Uses standard `vector<uintptr_t>` instead of custom typedef
- **Parameter Types**: Updated function parameters for consistency and safety

These improvements ensure the library compiles cleanly on modern Visual Studio versions and provides better reliability across different system architectures.

## Usage

```cpp
#include "SignatureScanner.h"

// Initialize
signature_scanner* sig = new signature_scanner();

// Search for pattern with wildcards
uintptr_t address = sig->search("3AB2DFAB????????3FBACD300200A1XXXXXXXXB1C4DA");

// Search for text
uintptr_t address = sig->search_text("Hello World");

// Find all matches
vector<uintptr_t> results;
bool found = sig->find_all(results, "pattern");
```

See the main project README for more detailed usage examples.