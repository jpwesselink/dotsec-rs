# Operations: Rotation & Incident Response

What to do when secrets change, when keys change, when people change, and when things go wrong. None of these should be "I'll figure it out in the moment" — they're the questions a serious security reviewer will ask, and the right time to answer them is *before* you need the answers.

## Rotation: routine

### Rotate a single secret

A value changed at its provider — Stripe key regenerated, OAuth client secret rolled, database password updated — and you need to update the `.sec` file:

```bash
dotsec set STRIPE_SECRET_KEY sk_live_new_value_here
```

That's it. `dotsec set` updates the value in-place using the existing DEK; the rest of the file's encrypted entries are untouched. CI on the next deploy picks up the new value via `dotsec run`. **The old plaintext was never written to disk.**

### Rotate the data encryption key (DEK)

After a suspected compromise, on a periodic schedule, or after offboarding someone who had the key file:

```bash
dotsec rotate-key
```

This decrypts every encrypted value with the old DEK, generates a fresh DEK, re-encrypts every value under the new DEK, and refreshes the `dek=` and `mac=` fields in the `@dotsec(...)` directive. Every `ENC[...]` blob in the file changes; the plaintext values do not.

For the local age provider, the DEK is wrapped under your existing `.sec.key`. For KMS, `rotate-key` calls `GenerateDataKey` for a fresh wrapped DEK. Either way: commit the new `.sec`, ship it.

:::tip Rotate the DEK does NOT rotate the secret values
If a value itself was leaked (Stripe key exposed in a log file), rotating the DEK does not help — the value was visible at its provider's API surface, not in the `.sec` file. **Rotate the actual secret at the provider, then `dotsec set` the new value.** Treat DEK rotation as orthogonal to value rotation; both have their place.
:::

### Rotate the keypair (local provider only)

After a key file leak or to ship a fresh keypair to a new team:

```bash
dotsec init          # generates new .sec.key + age recipient
dotsec rotate-key    # re-wraps the DEK with the new recipient
```

Then share the new `.sec.key` via your password manager and have everyone replace their local copy. For KMS, this isn't a thing — there's no keypair to rotate. You rotate the KMS key itself in AWS (`aws kms enable-key-rotation` for annual automatic rotation, or manual key migration if you need policy changes).

## Revocation: people changing

### Offboard a developer (local provider)

When someone leaves the team, the `.sec.key` file they had on disk is still valid forever. The model is "anyone with this file can decrypt." So:

```bash
dotsec init          # new keypair
dotsec rotate-key    # re-wrap DEK to new recipient
# distribute new .sec.key to remaining team, update CI secrets
```

There's no concept of "revoke just this person" with the local provider — rotation is the only mechanism. If your team turns over often, this is friction. The KMS provider exists partly because of this.

### Offboard a developer (KMS provider)

```bash
# Remove their IAM group membership (or remove the user, depending on your IAM model)
aws iam remove-user-from-group --user-name alice --group-name dotsec-readers
```

Done. Instant. They can no longer call `kms:Decrypt`, the wrapped DEK in the `.sec` file is opaque to them, no key file changes hands. **This is the structural reason to prefer KMS for any team larger than 1.**

You can also restrict their access to specific time windows or specific files via IAM conditions if you need more granularity — but plain group membership covers most use cases.

## Incident response

### A `.sec.key` (or `DOTSEC_PRIVATE_KEY` value) leaked

Treat **every value in every `.sec` file the key unlocks** as exposed. Decryption is now possible for anyone holding the leaked key.

1. **Rotate the affected secrets at their providers.** The Stripe key, the OAuth client secret, the database password — go to each provider's console, rotate, paste the new value into a `dotsec set` command.
2. **Generate a new keypair and rotate the DEK** so historical `.sec` files in git (which the attacker may have copied) become useless going forward:
   ```bash
   dotsec init && dotsec rotate-key
   ```
3. **Investigate the leak vector.** Was the key file committed accidentally? Did a backup tool copy it off-machine? Was it in a CI log? Close that path before redistributing the new key.
4. **Distribute the new keypair** to teammates via your password manager and update CI secrets.

Note: the values rotated at their providers (step 1) are the actual recovery. The DEK rotation (step 2) is hygiene — it stops future use of the leaked key, but it doesn't unleak values an attacker may already have decrypted.

### A KMS key was misused or compromised

If you suspect a principal with `kms:Decrypt` access decrypted things they shouldn't have:

1. **Query CloudTrail** to see exactly what was decrypted by whom and when. With encryption-context binding, every dotsec decrypt is filterable on `requestParameters.encryptionContext.dotsec:format=v3`:
   ```sql
   -- CloudWatch Insights / Athena
   fields @timestamp, userIdentity.principalId, sourceIPAddress
   | filter eventName = "Decrypt"
   |   and requestParameters.encryptionContext."dotsec:format" = "v3"
   | sort @timestamp desc
   ```
2. **Revoke the principal's access immediately** — remove the IAM grant or detach the policy.
3. **Rotate the affected secrets at their providers** (same as above — recovery happens at the source, not in the `.sec` file).
4. **Decide whether to rotate the KMS key itself.** Usually not needed because the key was used legitimately by an over-permissioned principal, not extracted from the HSM. Tighten IAM, rotate the secrets, move on. If you have reason to believe the KMS key material was extracted, that's an AWS support case.

### A compromised CI runner held `kms:Decrypt`

A malicious dependency ran in a CI job that had been granted KMS access, and it called `kms:Decrypt` on your wrapped DEKs and exfiltrated plaintext.

1. **Revoke the CI role's `kms:Decrypt` immediately** — block further decrypts while you investigate.
2. **CloudTrail will show exactly which `.sec` files were decrypted** during the compromise window (via encryption-context binding).
3. **Rotate every value that was decryptable from that role**, at its provider.
4. **Investigate the CI compromise**: which dependency, which install step, was it a lifecycle script that ran before the dotsec call, did the runner allow outbound traffic to the attacker's exfil endpoint?
5. **Harden the CI posture** so the same vector doesn't reopen — pin dependencies to SHA, separate the dependency-install job from the decrypt job, restrict outbound network egress where the platform supports it. See [CI/CD security posture](/guide/ci#cicd-security-posture).

### A value leaked from your application at runtime

A secret showed up in an application log, a crash report, a frontend bundle, a `docker inspect` output — somewhere downstream of `dotsec run`. dotsec didn't help here; the leak happened after decrypt.

1. **Rotate the leaked value at its provider** immediately — no DEK rotation needed because the `.sec` file isn't what leaked.
2. **Patch the leak source.** Scrub env vars from your log formatter / crash reporter, remove the `process.env.X` reference from frontend code, lock down access to the docker daemon, whatever the vector was.
3. **Document for the postmortem.** This is exactly what the "Runtime exposure dotsec does NOT solve" list in the [security model](/guide/security#runtime-exposure-dotsec-does-not-solve) names — your app and runtime own this surface.

## "Force re-encrypt" — `dotsec encrypt`

You edited a directive (`@encrypt` ↔ `@plaintext` toggle, `@push` target change), or you edited `dotsec.schema`, and the next `dotsec run` errors with an integrity-tag mismatch:

```
error: The .sec file has changed in a way dotsec can't verify.
```

That's the file-level MAC catching your intentional edit. To accept the new state:

```bash
dotsec encrypt
```

This re-runs the encrypt pipeline with the current DEK and refreshes the `mac=` field. Use it deliberately — running `dotsec encrypt` on a file someone else tampered with would silently legitimize the tamper. If you didn't change anything yourself, restore from git instead.

## Audit trail questions

Quick answers to "what does dotsec tell me about who did what?":

| Question | Local provider | AWS KMS provider |
|---|---|---|
| Who decrypted this file? | Not recoverable. Anyone with the key file can decrypt without leaving a trace. | CloudTrail records every `kms:Decrypt` with principal, timestamp, source IP, encryption context. |
| When was the DEK last rotated? | git log on `.sec` shows when the `dek=` field last changed. | Same. |
| Who edited the schema? | git log on `dotsec.schema`. | Same. |
| Did a recent run actually decrypt, or did it fail? | Not recoverable from the file. | CloudTrail shows successful and denied `kms:Decrypt` calls. |

The KMS column is the answer for any team that has compliance evidence requirements. The local provider is fine for solo / hobby / small-team use where "who did what" is socially answered.
