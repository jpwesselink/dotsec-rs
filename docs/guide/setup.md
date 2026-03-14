# Setup

## Required Secrets

Add these in **Settings → Secrets and variables → Actions** on the GitHub repo:

| Secret | Purpose | How to create |
|---|---|---|
| `CARGO_REGISTRY_TOKEN` | Publish crates to crates.io | [crates.io/settings/tokens](https://crates.io/settings/tokens) → New token with publish scope |
| `NPM_TOKEN` | Publish packages to npm | [npmjs.com/settings/tokens](https://www.npmjs.com/settings/~/tokens) → New Automation token |
| `RELEASE_TOKEN` | GitHub PAT for release-plz | GitHub → Settings → Developer settings → Fine-grained tokens (see below) |

## Creating the GitHub PAT (`RELEASE_TOKEN`)

1. Go to **GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens**
2. Click **Generate new token**
3. Set the token name (e.g. `release-plz`)
4. Set an expiration
5. Under **Repository access**, select only the repos that need it
6. Under **Repository permissions**, grant:
   - **Contents**: Read and write
   - **Pull requests**: Read and write
7. Click **Generate token** and copy the value
8. Add it as the `RELEASE_TOKEN` secret on the repo

## AWS Setup

dotsec uses AWS KMS for encryption. You need:

1. An AWS account with KMS access
2. A KMS key (or alias like `alias/dotsec`)
3. AWS credentials configured locally (`~/.aws/credentials` or environment variables)

```bash
# Create a KMS key alias
aws kms create-alias \
  --alias-name alias/dotsec \
  --target-key-id <your-key-id>
```

Then initialize dotsec:

```bash
dotsec init
# Follow the prompts to set provider, key ID, and region
```
