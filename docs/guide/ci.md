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

## CI/CD security posture

dotsec gives you the plumbing — KMS, OIDC, encryption context. The *posture* is yours to design. The questions below are what a serious security review will ask before signing off on a CI/CD pipeline that decrypts secrets. They're worth answering deliberately rather than discovering at audit time.

### Decrypt access scoping

| Question | Bad answer | Good answer |
|---|---|---|
| Who can decrypt **prod** secrets from CI? | "Any workflow run on this repo." | "Only workflows targeting protected branches, gated by [GitHub Environment](https://docs.github.com/en/actions/deployment/targeting-different-environments) protection with required reviewers on the prod environment." |
| Can a PR from a fork trigger a decrypt? | "We didn't think about it." | "No — `pull_request` workflows from forks don't get repo secrets and don't get the OIDC token needed to assume the prod IAM role. `pull_request_target` is reserved for vetted workflows that don't decrypt." |
| Same KMS key for dev / staging / prod? | "Yes, simpler." | "No — one KMS key per environment, separate `.sec` files, separate IAM roles. The dev CI role's policy literally can't `kms:Decrypt` the prod key." |
| Long-lived AWS access keys in GitHub Secrets? | "It works." | "OIDC + `aws-actions/configure-aws-credentials@v4` with `role-to-assume` and time-bounded session tokens. No static AWS creds anywhere in the workflow." |
| Where is `DOTSEC_PRIVATE_KEY` (local provider) used? | "Workflow-level env var, available to every step." | "Step-level env var on the single step that runs `dotsec run`. Forked-PR workflows can't see it because they don't get repo secrets." |

### Monitoring

| Question | Bad answer | Good answer |
|---|---|---|
| Do you monitor CloudTrail for dotsec decrypts? | "We have CloudTrail enabled somewhere." | "We filter CloudTrail for `kms:Decrypt` events with `requestParameters.encryptionContext.dotsec:format=v3`, route to our SIEM, and alert on principals that aren't in the expected set or on calls outside expected windows." |
| Do you know who decrypted what last week? | "We could probably reconstruct it." | "One Athena / CloudWatch Insights query against CloudTrail returns principal, time, source IP, and encryption context for every dotsec decrypt in the period." |

### Workflow hygiene (orthogonal to dotsec, but matters for the layered posture)

- **Pin actions to a SHA**, not `@v4`. Tag-based references can be hijacked.
- **Pin dependencies** via lockfiles, and run dependency review before merging upstream upgrades.
- **Don't run `kms:Decrypt` in jobs that install untrusted dependencies before the decrypt step.** A malicious `postinstall` script that runs *before* `dotsec run` and *after* `configure-aws-credentials` can call `aws kms decrypt` directly on your wrapped DEK and exfiltrate plaintext. Install dependencies in a separate prior job, or pin the dependency tree exhaustively.
- **Restrict outbound network egress** in workflows that handle production secrets where the platform supports it (GitHub-hosted runners support [allow-listing](https://docs.github.com/en/actions/reference/secure-use-reference)).
- **Set `permissions:` minimally** on every workflow — most don't need `write` access to anything.

### The TL;DR table for the security reviewer

| Layer | Mechanism | Failure mode it closes |
|---|---|---|
| At-rest secret storage | dotsec `.sec` file + KMS-wrapped DEK | Repo / disk / CI cache scrape |
| Per-decrypt access control | IAM policy with `kms:EncryptionContext:dotsec:format=v3` | Wrong principal calling `kms:Decrypt` |
| Per-decrypt audit | CloudTrail log per `kms:Decrypt` call | "Who decrypted this last week?" |
| Approval gate | GitHub Environment protection | Untrusted PR triggering prod decrypt |
| Identity federation | GitHub OIDC → AWS role assumption | Long-lived AWS keys getting leaked |
| Environment separation | Per-environment KMS key | Dev role reaching prod material |
| Dependency trust | Lockfiles + pinned actions + dependency review | Compromised package decrypting before `dotsec run` does |

If you can answer "yes" to all rows for production, you've got a posture, not just a tool.
