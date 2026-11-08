# Troubleshooting

The errors you're most likely to hit, what they mean, and how to get unstuck.

## "The .sec file has changed in a way dotsec can't verify"

The file-level integrity tag (MAC) doesn't match the file's current contents. Two possibilities:

1. **You (or a teammate) hand-edited the file** — added/removed/renamed a variable, edited a directive, edited the schema. To accept the new state:

   ```bash
   dotsec encrypt
   ```

   Tip: prefer `dotsec set` for routine edits — it re-MACs automatically.

2. **Someone tampered with the file.** Running `dotsec encrypt` now would bless the tamper. Restore from git first, then investigate.

See [the integrity tag](/guide/encryption#file-level-integrity-tag) for exactly what the MAC covers.

## "private key not found — set DOTSEC_PRIVATE_KEY or create .sec.key"

dotsec looked for a key in this order and found neither:

1. `DOTSEC_PRIVATE_KEY` environment variable
2. The key-file path in `@key-id`, if the `.sec` file sets one (local provider)
3. Otherwise `<sec-file>.key` next to the `.sec` file (so `.sec.staging` wants `.sec.staging.key`)

Common causes: fresh clone without the key (get it from a teammate over a secure channel), CI without the secret configured (see [CI/CD](/guide/ci)), or a multi-env setup where the key file doesn't match the `SEC_FILE` name.

## "bare directive `@encrypt` — directives must start with `#`"

Directives are comments. This fails to parse:

```bash
@encrypt
API_KEY="..."
```

This is correct:

```bash
# @encrypt
API_KEY="..."
```

## "inline @type directive not allowed" (when a schema exists)

Once a `dotsec.schema` file exists, per-key directives belong **in the schema** — inline copies in `.sec` would drift from it, so they're an error. Clean them up:

```bash
dotsec remove-directives
```

Then put the directive in `dotsec.schema` instead. See [directive classification](/guide/directives#directive-classification).

## "expected text_directive_value"

A directive that takes a value was written without one:

```bash
# @region=
```

Either give it a value (`# @region=us-east-1`) or remove the directive.

A related point: unquoted values may start with `#` or `//` and are kept as-is (`COLOR=#ff0000` is the value `#ff0000`, not a comment), and `export KEY=value` lines are accepted, so a shell-style `.env` imports unchanged.

## "KMS error: ..." on decrypt

Three usual suspects:

- **Wrong AWS credentials/region** — confirm `aws sts get-caller-identity` works and the region matches the `@region` directive.
- **Missing `kms:Decrypt` permission** on the key for your current principal.
- **Encryption-context mismatch** — the wrapped DEK is bound to `dotsec:format=v3`. A `.sec` file whose DEK was wrapped by a different tool (or a tampered context) won't unwrap.

For CloudTrail forensics: every dotsec decrypt shows up as a `kms:Decrypt` event with the principal, time, KMS key and the `dotsec:format=v3` encryption context. That context is the same for every `.sec` file, so CloudTrail can't tell you *which* file was decrypted. Use a KMS key per environment if you need that distinction.

## Key compromised or lost

**Compromised** (someone got `.sec.key`): replace the keypair and re-encrypt —

```bash
dotsec rotate-key --new-keypair   # new age identity + new DEK, replaces the key file
```

Then update `DOTSEC_PRIVATE_KEY` wherever it's set (CI secrets) and share the new key file over a secure channel. Treat every value in the file as exposed and rotate the actual secrets (API keys, passwords) at their providers. The attacker had the ciphertext *and* the key, and every older `.sec` in git history stays decryptable with the old key. See [Operations → incident response](/guide/operations#incident-response).

**Lost** (no backup of `.sec.key`, no `DOTSEC_PRIVATE_KEY` anywhere): the encrypted values are unrecoverable — that's the point of the encryption. Re-create the `.sec` from the source secrets (your password manager, the provider dashboards) with a fresh keypair. To avoid this, store `.sec.key` in your team's password manager as soon as it's generated.

## FAQ

### How do I stop using dotsec?

```bash
dotsec export -o .env    # decrypt everything to a plain .env
rm .sec .sec.key         # remove dotsec artifacts
```

Your `.env` works like it always did. No lock-in — and because the wrapped DEK is a standard [age](https://age-encryption.org/) envelope, even a broken dotsec install wouldn't strand your data.

### Can I encrypt to multiple teammates' keys?

Not yet — one keypair per `.sec` file today, shared over a secure channel. Multi-recipient support (per-teammate keys, painless offboarding) is planned; age's envelope format supports it natively.

### Does `.sec` belong in git? Really?

Yes — that's the model. Values are AES-256-GCM encrypted, names are integrity-protected, and the [threat model](/guide/security) assumes the file is public. What must never be committed is `.sec.key` (auto-`.gitignore`d on first run).

### A secret leaked into git history inside an old `.sec` — what now?

Neither `dotsec rotate-key` nor `dotsec rotate-key --new-keypair` helps for values that were already exposed under the old key — anyone with the old file + old key can still decrypt them. Rotate the underlying secret at its provider, then `dotsec set` the new value.

### Why is my `PORT=3000` not encrypted?

New projects get `@default-encrypt`, so values are encrypted unless something opted them out: `--plaintext` on `dotsec set`, an `@plaintext` directive (inline or in `dotsec.schema`), or `@default-plaintext` at file level. With `-y`, `set` and `import` auto-detect directives and mark values that don't look like secrets (`PORT=3000`, `DEBUG=true`) `@plaintext`. `dotsec show` masks *every* value, plaintext included, so it can't tell you what's encrypted; look in the `.sec` file itself, where encrypted values appear as `ENC[...]`.
