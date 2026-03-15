# @dotsec/core

Native Node.js bindings for [dotsec](https://github.com/jpwesselink/dotsec-rs) — parse, validate, and format `.env` files with directive support.

## Install

```bash
npm install @dotsec/core
```

## Usage

```js
import { parse, validate, toJson, format } from '@dotsec/core';

// Parse .env content into structured entries
const entries = parse(`
# @encrypt
DB_URL="postgres://localhost"
DEBUG=true
`);
// [
//   { key: "DB_URL", value: "postgres://localhost", quoteType: "Double", directives: [{ name: "encrypt" }] },
//   { key: "DEBUG", value: "true", quoteType: "None", directives: [] }
// ]

// Validate directives and values
const errors = validate('# @bogus\nFOO="bar"\n');
// [{ key: "FOO", message: "unknown directive @bogus..." }]

// Convert to JSON
const json = toJson('FOO=bar\nPORT=3000\n');
// '[{"FOO":"bar"},{"PORT":"3000"}]'

// Roundtrip format
const formatted = format('FOO=bar\n');
// 'FOO=bar\n'
```

## Supported directives

- `@encrypt` / `@plaintext` — mark variables for encryption
- `@default-encrypt` / `@default-plaintext` — file-level defaults
- `@type=string|number|boolean|enum("a","b")` — value type validation
- `@push=aws-ssm|aws-secrets-manager` — push targets with options
- `@provider`, `@key-id`, `@region` — file-level encryption config

See the [full documentation](https://jpwesselink.github.io/dotsec-rs/beta/guide/directives.html) for details.

## Platforms

Pre-built binaries are available for:

- macOS (ARM64, x64)
- Linux (ARM64, x64, glibc)
- Windows (ARM64, x64)

## License

MIT — [github.com/jpwesselink/dotsec-rs](https://github.com/jpwesselink/dotsec-rs)
