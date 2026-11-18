# envmgr

A terminal UI and CLI environment variable manager with layered collections, encrypted local storage, live shell synchronization, and optional [Phase.dev](https://phase.dev) integration.

---

## Why `envmgr`?

If you can already put variables in `~/.bashrc`, system settings, or run a secret manager CLI like `phase` directly, why use another tool?

- **System & shell configs don't scale across contexts.** Storing variables in `~/.bashrc` or `.env` files leaves secrets in plaintext on disk, makes switching between projects or environments error-prone, and leaves stale variables exported in open terminals until you manually `unset` them or restart your shell.
- **Secret manager CLIs aren't built for everyday local overrides.** Running commands through `phase run` wraps every invocation, assumes network availability, and makes it awkward to toggle temporary local overrides alongside remote secrets.

`envmgr` bridges both workflows:

- **Layered collections with top-wins priority** — Organize variables into independent collections (such as `default`, `staging`, or `local-overrides`), toggle any collection or individual variable on/off, and reorder priority so the highest collection overrides duplicate keys.
- **Live shell sync without restarting** — Saving updates your active terminal immediately and automatically refreshes other open Bash sessions on their next prompt, cleanly unsetting variables from disabled collections.
- **Encrypted at rest, offline-first** — Secrets are stored in an encrypted local file (`~/.config/envmgr/state.enc`) rather than plaintext in `~/.bashrc`, so everything works offline while still letting you pull from Phase.dev when needed.
- **Manual and remote secrets side by side** — Combine custom local variables and Phase.dev-synced collections in one effective environment without mixing or overwriting your manual entries.

---

## Installation

### Quick Install (Prebuilt Binary)

Install the latest release binary for Linux (`x86_64`, `aarch64`) or macOS (`Intel`, `Apple Silicon`):

```sh
curl -fsSL https://raw.githubusercontent.com/dsnbyte/envmgr/main/install.sh | sh
```

By default, the binary is installed to `~/.local/bin/envmgr`. You can customize the installation directory or target a specific release version:

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

Ensure `~/.local/bin` is included in your `PATH`.

### Shell Setup

Run `envmgr` once to open the TUI (or run `envmgr reload`). `envmgr` automatically registers a small shell hook in `~/.bashrc` to evaluate active variables in new shells, wrap `envmgr` for instant in-session updates, and sync changes across open terminals. Plaintext secret names and values are never written to `~/.bashrc`.

---

## Usage

### CLI Commands

| Command | Description |
|---|---|
| `envmgr` | Launch the interactive TUI |
| `envmgr reload` | Save encrypted state, verify `~/.bashrc` integration, and reload the active shell |
| `envmgr apply` | Alias for `envmgr reload` |
| `envmgr sync` | Sync all Phase.dev-backed collections using configured authentication |
| `envmgr export` | Print shell `export` / `unset` statements for the effective environment |
| `envmgr status` | Show store location, Phase.dev status, collections, and effective variables |
| `envmgr --help` | Print CLI usage information |

### TUI Keyboard Shortcuts

| Key | Action |
|---|---|
| `Ctrl+N` | Create a new collection |
| `Space` | Toggle selected collection or variable on/off |
| `u` / `d` | Move selected collection priority up / down (top wins) |
| `Ctrl+A` | Add a custom variable |
| `Ctrl+E` / `Enter` | Edit selected collection or variable |
| `Delete` | Delete selected collection or variable |
| `Ctrl+R` | Show or hide masked secret values |
| `Ctrl+B` | Sync selected Phase.dev collection |
| `Ctrl+Shift+B` | Sync all Phase.dev collections |
| `Ctrl+S` | Save encrypted state and reload shell environment |
| `Ctrl+P` | Open settings (Phase.dev connection & preferences) |
| `Tab` / `Shift+Tab` | Switch focus between panes |
| `?` | Toggle help overlay |
| `q` | Quit |

Mouse navigation and context menus are also supported inside the TUI.

---

## Phase.dev Integration (Optional)

`envmgr` works standalone without an account. When you want to pull secrets from Phase.dev:

1. Press `Ctrl+P` to open Settings and configure your Phase.dev connection (either **Phase CLI** authentication or a **Personal / Service Token** for Cloud or Self-Hosted instances).
2. Press `Ctrl+N` and choose to pull from Phase.dev to bind a new collection to an app and environment.
3. Press `Ctrl+B` to sync the selected collection, `Ctrl+Shift+B` to sync all Phase.dev collections, or run `envmgr sync` from the CLI.

Phase-synced collections and manual collections remain cleanly separated by source so remote syncs never overwrite local custom variables.
