# CI/CD

dotsec needs exactly one thing in CI: the ability to unwrap the DEK. For the local provider that's the `DOTSEC_PRIVATE_KEY` env var; for AWS KMS it's IAM credentials. No files to write, no extra setup step.

## GitHub Actions (local provider)

Add the contents of your `.sec.key` as a repository secret (Settings → Secrets and variables → Actions), e.g. `DOTSEC_PRIVATE_KEY`. Then:

```yaml
name: test
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm ci
      - run: npx dotsec run -- npm test
        env:
          DOTSEC_PRIVATE_KEY: ${{ secrets.DOTSEC_PRIVATE_KEY }}
```

That's the whole integration. `dotsec run` decrypts `.sec` in memory and injects the env vars into `npm test`. Nothing plaintext ever touches the runner's disk, and encrypted values are redacted from the job log if your process echoes them.

:::tip Scope the secret to the env var
Pass `DOTSEC_PRIVATE_KEY` on the *step* that needs it (as above), not at the job or workflow level. Smaller exposure window, and forked-PR workflows never see it.
:::

## GitHub Actions (AWS KMS + OIDC)

With the KMS provider there's no dotsec key to manage at all — IAM is the keychain. Use GitHub's OIDC federation so there are no long-lived AWS credentials either:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/ci-dotsec
          aws-region: us-east-1
      - run: npx dotsec run -- npm test
```

The assumed role needs `kms:Decrypt` on your dotsec key. You can pin the permission to dotsec files specifically using the encryption context:

```json
{
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": "arn:aws:kms:us-east-1:123456789012:key/...",
  "Condition": {
    "StringEquals": { "kms:EncryptionContext:dotsec:format": "v3" }
  }
}
```

Every decrypt also lands in CloudTrail with that context attached — a free audit trail of which principal decrypted when.

## GitLab CI

```yaml
test:
  image: node:22
  script:
    - npm ci
    - npx dotsec run -- npm test
  variables:
    # Set DOTSEC_PRIVATE_KEY as a masked + protected CI/CD variable
    # (Settings → CI/CD → Variables); it's inherited here automatically.
```

## Anything else

Every CI system reduces to the same two lines:

```bash
export DOTSEC_PRIVATE_KEY="AGE-SECRET-KEY-1..."   # or AWS credentials for KMS
dotsec run -- <your command>
```

dotsec checks `DOTSEC_PRIVATE_KEY` before looking for a `.sec.key` file, so the env var always wins — see [key discovery](/guide/encryption#key-file).

## Things to avoid

- **Don't `dotsec export -o .env` in CI.** It writes plaintext to disk where later steps, caches, or artifacts can pick it up. `dotsec run` keeps secrets in memory.
- **Don't echo `dotsec show --reveal` into logs.** Masked-by-default `dotsec show` exists for a reason.
- **Don't commit `.sec.key` to make CI work.** That defeats the whole model — use the env var.

## dotsec knobs that matter in CI

A few configuration items specific to dotsec are worth getting right. Everything else about CI/CD security — workflow approvals, OIDC trust policies, dependency review, action pinning — is your standard cloud-security posture and lives in your existing platform docs, not here.

| Knob | Why it matters |
|---|---|
| **Pin `kms:Decrypt` to the `dotsec:format=v3` encryption context** in your IAM policy | Without this condition, the role can decrypt *anything* that key wraps. With it, the role can only decrypt dotsec-produced wrapped DEKs. See the IAM snippet [above](#github-actions-aws-kms--oidc). |
| **Separate KMS keys per environment** (dev / staging / prod) | A dev CI role with `kms:Decrypt` on the dev key can't reach prod material even if it tries. Single-key setups make this an IAM-condition problem instead of a structural one. |
| **Step-level secret scoping for `DOTSEC_PRIVATE_KEY`** (local provider) | Pass it on the single step that runs `dotsec run`, not the workflow or job env. Smaller exposure window; forked-PR workflows can't see it because they never get repo secrets. |
| **CloudTrail filter on `requestParameters.encryptionContext.dotsec:format=v3`** | One Athena / CloudWatch Insights query returns every dotsec decrypt with principal, timestamp, source IP. Useful for incident response and for compliance evidence. |
