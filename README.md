# envmgr

Super lightweight TUI environment manager written in Rust with whole-state AEAD encryption (`ChaCha20-Poly1305`), Phase.dev sync, and zero-plaintext runtime bash shell injection.

---

## Quick Setup

1. **Build & Symlink**:
   ```bash
   cargo build --release
   mkdir -p ~/.local/bin
   ln -sf "$(pwd)/target/release/envmgr" ~/.local/bin/envmgr
   ```
   Now you can run `envmgr` from anywhere.

2. **Shell Integration**:
   Run `envmgr` once or run `envmgr reload`. It stores your entire state encrypted in `~/.config/envmgr/state.enc` and adds a tiny runtime hook (`eval "$(command envmgr export 2>/dev/null)"`) to `~/.bashrc`.
   - Plaintext variable names and secret values are **never** written to disk or `.bashrc`.
   - The `envmgr` shell wrapper function automatically evaluates updated variables in your active terminal session whenever you exit the TUI or run `envmgr reload`—no need to manually run `source ~/.bashrc`.

---

## How It Works

- **Encrypted State (`state.enc`)**:
  - Collections, variable keys, values, and Phase.dev tokens are serialized and encrypted with `ChaCha20-Poly1305` using a hardcoded source key (`HARDCODED_MASTER_KEY` in `src/model.rs`). Changing the encryption key requires updating the source code and rebuilding.
- **Collections & Priority**:
  - `Collections`: Can be toggled on/off independently. A predefined `default` collection is provided on initial setup and can be edited, renamed, deleted, or toggled like any other collection.
  - `Priority (Top Wins)`: When multiple collections are enabled, the collection highest in the list (index #1) takes precedence and overwrites duplicate keys from lower collections. Reorder collection priority anytime using `u` (move up) or `d` (move down).
- **Clean Unsets**:
  - When you disable a collection, its variables don't linger in your shell session—`envmgr` tracks exported keys via `_ENVMGR_KEYS` and unsets removed ones on reload.

---

## Phase.dev Sync (Optional)

Phase.dev connection is completely optional. You can use `envmgr` 100% offline with manual variables.

When you want to sync secrets from Phase.dev:
1. Press `c` to open the connection dialog.
2. Select **Cloud** (uses `https://console.phase.dev`) or **Self-Hosted** (enter your custom console URL).
3. Paste your Personal Access Token (PAT) or Service Token (`pss_user:v1:...` / `pss_service:v2:...`).
4. Pull secrets into an existing collection (`p`) or when creating a new collection (`n`).
5. Custom manual variables and Phase secrets coexist in the same collection.

---

## Keyboard Shortcuts

| Key | Action |
|---|---|
| `Ctrl+N` | Create a new collection |
| `Space` | Toggle selected collection or variable ON / OFF |
| `u` / `d` | Move collection priority up / down |
| `Ctrl+A` | Add a custom environment variable |
| `Ctrl+E` / `Enter` | Edit selected collection or variable |
| `Delete` | Delete selected collection or variable |
| `Ctrl+R` | Show or hide masked secret values |
| `Ctrl+B` | Sync selected environment |
| `Ctrl+Shift+B` | Sync all environments |
| `Ctrl+S` | Save encrypted state and reload shell environment |
| `Ctrl+P` | Open application settings |
| `Tab` / `Shift+Tab` | Cycle focus between panes |
| `?` | Toggle shortcut info & help |
| `q` | Quit application |

---

## CLI Subcommands

- `envmgr` — Launch interactive TUI.
- `envmgr reload` (or `envmgr apply`) — Save encrypted `state.enc`, verify `~/.bashrc`, and reload active shell environment.
- `envmgr export` — Decrypt active variables from `state.enc` and output shell export statements to stdout.
- `envmgr status` — Print active collections and effective variable breakdown.

---

## Development Note

Because `~/.local/bin/envmgr` points to `target/release/envmgr`, **always build in release mode** after code changes:
```bash
cargo test && cargo build --release
```
