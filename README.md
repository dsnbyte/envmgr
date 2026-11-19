# envmgr

A fast, lightweight terminal UI for managing shell environment variables—with layered collections, live cross-terminal sync, and optional [Phase.dev](https://phase.dev) integration.

## Why `envmgr`?

Plaintext `~/.bashrc` exports and scattered `.env` files don't scale across projects—switching contexts is error-prone, and removed variables linger in open terminals until you manually `unset` them or restart your shell. Secret manager CLIs solve storage, but wrap every command, assume network access, and make quick local overrides awkward.

`envmgr` bridges both workflows in a single Rust binary:

- **Layered collections (top wins)** — Group variables by context (such as `default`, `staging`, or `local-overrides`), toggle entire collections or individual keys on/off, and reorder priority so higher layers override duplicate keys.
- **Live cross-terminal sync** — Saving updates your active Bash session immediately and refreshes other open terminals on their next prompt, cleanly unsetting variables from disabled collections.
- **Encrypted at rest, offline-first** — Secrets stay encrypted locally rather than sitting in plaintext in `~/.bashrc`, with full offline support.
- **Local & remote secrets side by side** — Layer custom local variables on top of Phase.dev-synced collections without mixing or overwriting your manual entries.

## Installation

### Prebuilt Binary

Install the latest release for Linux (`x86_64`, `aarch64`) or macOS (`Intel`, `Apple Silicon`):

```sh
curl -fsSL https://raw.githubusercontent.com/dsnbyte/envmgr/main/install.sh | sh
```

Installs to `~/.local/bin/envmgr` by default. You can override the target directory or pin a release version:

```sh
curl -fsSL https://raw.githubusercontent.com/dsnbyte/envmgr/main/install.sh | ENVMGR_INSTALL_DIR=/usr/local/bin ENVMGR_VERSION=v0.1.0 sh
```

### Build from Source

Requires the [Rust toolchain](https://rustup.rs/):

```sh
git clone https://github.com/dsnbyte/envmgr.git
cd envmgr
cargo build --release
mkdir -p ~/.local/bin
ln -sf "$(pwd)/target/release/envmgr" ~/.local/bin/envmgr
```

### Shell Integration

Run `envmgr` once to launch the TUI. It automatically adds a minimal hook to `~/.bashrc` to load active variables in new shells and sync changes across open terminals. Plaintext secret names and values are never written to `~/.bashrc`.

## Usage

Run `envmgr` to open the interactive TUI (controls are built into the interface, with full mouse support). A few subcommands are also available for scripting and shell automation:

| Command | Description |
|---|---|
| `envmgr` | Launch the interactive TUI |
| `envmgr sync` | Sync all Phase.dev-backed collections |
| `envmgr reload` | Re-verify shell integration and reload the active session (`apply` alias) |
| `envmgr status` | Inspect collections, effective variables, and Phase.dev status |
| `envmgr export` | Print `export` / `unset` statements for the effective environment |

## Phase.dev Integration (Optional)

`envmgr` works completely standalone without an account. When you want to pull remote secrets from [Phase.dev](https://phase.dev):

- **Cloud or Self-Hosted** — Connect to Phase Cloud or your own self-hosted instance.
- **Flexible authentication** — Authenticate through an existing Phase CLI session or a Personal / Service Token with built-in end-to-end decryption.
- **App & environment binding** — Bind collections to any Phase app and environment, and pull updates on demand from the TUI or via `envmgr sync`.
- **Safe local overrides** — Remote-synced and manual collections stay cleanly separated, so syncing never overwrites your local custom variables.
