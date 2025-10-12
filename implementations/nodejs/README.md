# Node.js Signature Scanner

Node.js port of the Signature Scanner library for buffer/memory pattern scanning.

## Installation

```bash
npm install
```

## Usage

```javascript
const scanner = require('./SigScanner');

const buffer = Buffer.from(/* your data */);
const result = scanner.scan(buffer, {
    string: "Hello World",
    encoding: 'utf8'
});

console.log(result.found); // Array of found positions
```

## API

- `scan(buffer, query, callback)` - Scan buffer for patterns
- `version()` - Get library version

See the main project README for more detailed usage examples.