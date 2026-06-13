# Library Usage

Use dotsec programmatically — parse, validate, and generate code from `.env` / `.sec` / `dotsec.schema` files.

> The libraries handle **parsing and validation only**. Encryption and decryption stay in the CLI — no key material ever crosses the library boundary. This is deliberate; see the [security model](/guide/security#engineering-posture).

## Start here: typed env vars, zero dependencies

The highest-leverage feature doesn't even need the library at runtime — generate validation code from your schema and ship it:

```bash
dotsec schema export --format ts -o src/env.ts
```

```ts
import { parseEnv } from './env';

const env = parseEnv();  // validates at startup, throws on error
env.PORT;                // number
env.NODE_ENV;            // "development" | "staging" | "production"
```

The generated file *is* the validator — no runtime dependency on dotsec at all. See [`dotsec schema export`](/guide/commands#dotsec-schema-export).

## Node.js — `@dotsec/core`

Native bindings (NAPI, prebuilt per platform — no Rust toolchain needed):

```bash
npm install @dotsec/core
```

### Parse, validate, convert

```js
import {
  parse, validate, toJson, format,
} from '@dotsec/core';
import { readFileSync } from 'node:fs';

const source = readFileSync('.env', 'utf8');

// Parse into structured entries
const entries = parse(source);
for (const entry of entries) {
  console.log(`${entry.key} = ${entry.value}`);
}

// Validate directives (@type, @format, @pattern, @min/@max, ...)
const errors = validate(source);
for (const err of errors) {
  console.error(`[${err.severity}] ${err.key}: ${err.message}`);
}

// Convert to JSON or normalize formatting
const json = toJson(source);
const formatted = format(source);
```

### Schema operations

```js
import {
  loadSchema, discoverSchema, validateAgainstSchema,
  formatBySchema, parseSchema,
  schemaToJsonSchema, schemaToTypescript,
} from '@dotsec/core';
import { readFileSync } from 'node:fs';

// Auto-discover and load schema
const schema = loadSchema();           // finds dotsec.schema, returns entries or null
const path = discoverSchema('.sec');   // just returns the path or null

// Validate .env against schema
const source = readFileSync('.env', 'utf8');
const schemaSource = readFileSync('dotsec.schema', 'utf8');
const errors = validateAgainstSchema(source, schemaSource);

// Reorder .env to match schema key ordering
const reordered = formatBySchema(source, schemaSource);

// Generate JSON Schema or TypeScript from schema
const jsonSchema = schemaToJsonSchema(schemaSource);   // JSON string
const typescript = schemaToTypescript(schemaSource);   // TypeScript code string
```

### Header helpers

```js
import { generateHeader, hasHeader } from '@dotsec/core';

generateHeader();        // the standard .sec banner lines
hasHeader(source);       // does this file carry one?
```

## Rust — `dotsec-core`

> **Note:** `dotsec-core` is not published to crates.io (the obvious crate names are owned by unrelated projects). Use a git dependency:

```toml
[dependencies]
dotsec-core = { git = "https://github.com/jpwesselink/dotsec-rs" }
```

```rust
use dotsec_core::dotenv::{parse_dotenv, lines_to_entries, validate_entries};

let content = std::fs::read_to_string(".env").unwrap();
let lines = parse_dotenv(&content).unwrap();
let entries = lines_to_entries(&lines);

for entry in &entries {
    println!("{} = {}", entry.key, entry.value);
}

let errors = validate_entries(&entries);
for err in &errors {
    eprintln!("[{:?}] {}: {}", err.severity, err.key, err.message);
}
```
