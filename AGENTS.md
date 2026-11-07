# Agent Instructions for `envmgr`

## Project Status & Clean Code Policy
- **Active Development (Zero Users)**: This project is under active greenfield development with no external users. **Backward compatibility is not a concern**.
- **Prioritize Clean, Optimal Code**: Never introduce legacy shims, deprecated adapters, or migration boilerplate. Refactor freely and delete obsolete logic to keep the codebase clean, direct, and optimal.

## Build & Verification Mandate
- **Always build in release mode after changes**: After completing any task or making modifications to Rust source files, run:
  ```bash
  cargo test && cargo build --release
  ```
  A symlink at `~/.local/bin/envmgr` points directly to `target/release/envmgr`. Failing to build means the user will run outdated binaries outside this directory.

## Core Architecture Principles
- **Keep it Lightweight**: Avoid adding heavy dependencies or large runtime frameworks (such as SQLite/C database engines). Maintain sub-millisecond startup, small binary size, and zero external runtime dependencies.
- **Priority Resolution Rule**:
  - `Default` variables serve as baseline values.
  - Enabled profiles override `Default`.
  - When multiple profiles are enabled, the profile highest in the list (index #1) takes precedence and overwrites duplicate keys from lower profiles.
- **Encrypted State Storage & Runtime Shell Injection**:
  - All state (variables, keys, profiles, and Phase PAT tokens) is serialized as JSON and encrypted as a whole payload using **ChaCha20-Poly1305** AEAD (with a hardcoded master key in `src/model.rs`) into `~/.config/envmgr/state.enc` (or `$ENVMGR_CONFIG_DIR/state.enc`).
  - Never write plaintext variable names or values to disk or into `~/.bashrc`.
  - `~/.bashrc` only contains the runtime evaluation hook (`eval "$(command envmgr export 2>/dev/null)"`) and the `envmgr()` shell wrapper function so variables are automatically injected into the active terminal session without manually running `source ~/.bashrc`.
  - Always clean up removed variables on reload (via `_ENVMGR_KEYS` unsetting).
- **Phase.dev Decryption**:
  - Direct REST E2EE client using personal/service access tokens (`pss_user:` / `pss_service:`).
  - Preserves custom manual variables when synchronizing Phase secrets.
  - Offline/unconfigured state must never block local variable and profile management.
