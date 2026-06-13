---
pageType: home
hero:
  name: dotsec
  text: No more .env files
  tagline: KMS-native envelope encryption, schema-driven validation, language-agnostic runtime injection. Your secrets' access boundary is your existing IAM. Your audit trail is your existing CloudTrail.
  actions:
    - theme: brand
      text: Get Started →
      link: /guide/
    - theme: alt
      text: npm install -g dotsec
      link: /guide/setup
features:
  - icon: 🔐
    title: KMS-native, AWS-integrated
    details: Envelope encryption with EncryptionContext binding on every wrap and unwrap. IAM controls access; CloudTrail logs every decrypt. Push to SSM Parameter Store and Secrets Manager via @push directives, for runtime services that read from AWS directly.
    link: /guide/setup#aws-kms-setup
  - icon: 🧪
    title: Engineered like crypto matters
    details: AAD-bound per-value AEAD, file-level MAC over canonical content, schema-hash binding, key commitment, length padding, zeroize on every exit path, constant-time integrity checks. Cargo-fuzz harness with 4 targets. Visible in the source.
    link: /guide/security
  - icon: ✅
    title: Schema-driven validation
    details: Directives like @type, @format, @pattern, @min/@max enforce rules on every secret. Generate a zero-runtime-dependency TypeScript validator from your schema in one command — the generated file IS the validator.
    link: /guide/library#start-here-typed-env-vars-zero-dependencies
  - icon: 🚀
    title: Works with anything
    details: dotsec run -- <your command>. No SDK per language. Works for Node, Python, Ruby, Go, Rust, Docker, kubectl, terraform — anything that reads environment variables.
    link: /guide/commands#dotsec-run
  - icon: 🛡️
    title: Redacted output
    details: When dotsec run spawns your process, encrypted values are scrubbed from stdout and stderr before they hit your terminal or CI logs. The "accidentally console.log()'d a secret" class of bug is defended against by default.
    link: /guide/commands#dotsec-run
  - icon: 🔓
    title: Standard age envelope — no lock-in
    details: The wrapped DEK is a plain age envelope. Anyone with the private key can decrypt it with the age or rage CLI directly — your secrets are never trapped in a bespoke format.
    link: /guide/encryption#why-age
---

## What is a `.sec` file?

A `.sec` file is your `.env` file, encrypted. Same `KEY=value` shape, same workflow — except the values are AES-256-GCM encrypted and the file is safe to commit to git.

Your code keeps reading `process.env.X` (or `os.environ`, or `ENV[]`, whichever applies). The plaintext only exists in memory while your app is running under `dotsec run`.

### Before — `.env` (gitignored, plaintext)

```bash
DATABASE_URL=postgres://user:pass@localhost:5432/myapp
API_KEY=sk_live_xY9abc...
PORT=3000
```

### After — `.sec` (committed, encrypted)

```bash
# @dotsec(format=v3, mac=base64-32-bytes..., dek=base64-wrapped-dek...)

# @encrypt
DATABASE_URL=ENC[base64...]

# @encrypt
API_KEY=ENC[base64...]

PORT=3000
```

`dotsec import` does the transformation in one command. Commit `.sec`, delete `.env`, run your app the same way you always have — `dotsec run -- <your command>` decrypts in memory and injects the env vars into your process. No code change, no SDK, no plaintext on disk.

## …and you can have types on them

Add `@type`, `@format`, `@min`/`@max`, or `@enum` directives to constrain values. `dotsec validate` enforces them on every load — and the same directives generate a TypeScript validator with zero runtime dependencies.

```bash
# @encrypt @type=string @format=url @not-empty
DATABASE_URL=ENC[base64...]

# @encrypt @type=string @min-length=32
API_KEY=ENC[base64...]

# @type=number @min=1024 @max=65535
PORT=3000

# @type=enum("development", "staging", "production")
NODE_ENV=production
```

Then run:

```bash
dotsec schema export --format ts -o src/env.ts
```

and import the generated validator anywhere in your app:

```ts
import { parseEnv } from './env';

const env = parseEnv();   // validates at startup, throws on error
env.PORT;                 // number
env.NODE_ENV;             // "development" | "staging" | "production"
env.DATABASE_URL;         // string (validated as URL)
env.API_KEY;              // string, 32+ chars
```

The generated file *is* the validator — no `import 'dotsec'` at runtime, nothing to keep in sync, no SDK version drift. JSON Schema export (`--format json`) works the same way.
