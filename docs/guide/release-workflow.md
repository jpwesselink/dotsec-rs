# Release Workflow

Versioning is fully automated using [conventional commits](https://www.conventionalcommits.org/) and [release-plz](https://release-plz.ieni.dev/).

## Channels

| Channel | Trigger | npm tag | crates.io | Version format |
|---|---|---|---|---|
| **beta** | Push to `main` | `beta` | No | `{version}-beta.{sha}` |
| **pr** | PR commit | `pr-{N}` | No | `{version}-pr-{N}.{sha}` |
| **stable** | Release PR merge | `latest` | Yes | `{version}` |

Version is read from `Cargo.toml` (managed by release-plz via conventional commits).

## How it works

1. Conventional commits land on `main` (`feat:`, `fix:`, `feat!:`)
2. release-plz opens a "chore: release" PR with bumped versions
3. You merge the PR
4. release-plz publishes to crates.io and creates a GitHub release
5. The GitHub release automatically triggers the npm stable publish (`latest` tag)

## Commit message → version bump

| Commit | Bump |
|--------|------|
| `fix: handle empty values` | patch (`5.0.0` → `5.0.1`) |
| `feat: add push command` | minor (`5.0.0` → `5.1.0`) |
| `feat!: redesign directive syntax` | major (`5.0.0` → `6.0.0`) |

## CI Workflows

| Workflow | Description |
|---|---|
| **Publish CLI to NPM** | Builds CLI binary for 6 platforms, publishes `dotsec` |
| **Release-plz** | Analyzes conventional commits, creates release PRs, publishes to crates.io |

## Why no crates.io for PRs?

crates.io versions are permanent — you can't delete them, only yank. Publishing a crate for every PR commit would pollute the version history. npm has dist-tags so pre-releases are only visible when explicitly requested.
