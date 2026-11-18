#!/usr/bin/env sh
set -eu

REPO="${ENVMGR_REPO:-dsnbyte/envmgr}"
INSTALL_DIR="${ENVMGR_INSTALL_DIR:-${HOME}/.local/bin}"
VERSION="${ENVMGR_VERSION:-latest}"
BIN_NAME="envmgr"

log() {
    printf '%s\n' "$*"
}

err() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "Required command '$1' was not found."
    fi
}

download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        err "Either 'curl' or 'wget' is required to download ${BIN_NAME}."
    fi
}

detect_target() {
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)
            os_target="unknown-linux-musl"
            ;;
        Darwin)
            os_target="apple-darwin"
            ;;
        *)
            err "Unsupported OS '$os'. Please build from source with 'cargo build --release'."
            ;;
    esac

    case "$arch" in
        x86_64 | amd64)
            arch_target="x86_64"
            ;;
        aarch64 | arm64)
            arch_target="aarch64"
            ;;
        *)
            err "Unsupported architecture '$arch'. Please build from source with 'cargo build --release'."
            ;;
    esac

    printf '%s-%s' "$arch_target" "$os_target"
}

verify_checksum() {
    archive_path="$1"
    archive_name="$2"
    checksums_path="$3"

    expected="$(awk -v file="$archive_name" '$2 == file || $2 == ("./" file) { print $1; exit }' "$checksums_path")"
    if [ -z "$expected" ]; then
        log "Warning: checksum entry for ${archive_name} not found; skipping verification."
        return 0
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$archive_path" | awk '{ print $1 }')"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$archive_path" | awk '{ print $1 }')"
    else
        log "Warning: neither 'sha256sum' nor 'shasum' found; skipping checksum verification."
        return 0
    fi

    if [ "$actual" != "$expected" ]; then
        err "Checksum mismatch for ${archive_name} (expected ${expected}, got ${actual})."
    fi
}

main() {
    need_cmd tar
    need_cmd mktemp
    need_cmd uname

    target="$(detect_target)"
    archive_name="${BIN_NAME}-${target}.tar.gz"

    if [ "$VERSION" = "latest" ]; then
        base_url="https://github.com/${REPO}/releases/latest/download"
    else
        case "$VERSION" in
            v*) tag="$VERSION" ;;
            *) tag="v${VERSION}" ;;
        esac
        base_url="https://github.com/${REPO}/releases/download/${tag}"
    fi

    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT INT TERM

    archive_path="${tmp_dir}/${archive_name}"
    checksums_path="${tmp_dir}/checksums.txt"

    log "Downloading ${BIN_NAME} (${VERSION}) for ${target}..."
    download "${base_url}/${archive_name}" "$archive_path" \
        || err "Failed to download ${base_url}/${archive_name}."

    if download "${base_url}/checksums.txt" "$checksums_path" 2>/dev/null; then
        verify_checksum "$archive_path" "$archive_name" "$checksums_path"
    fi

    tar -xzf "$archive_path" -C "$tmp_dir"
    if [ ! -f "${tmp_dir}/${BIN_NAME}" ]; then
        err "Archive did not contain expected '${BIN_NAME}' binary."
    fi

    mkdir -p "$INSTALL_DIR"
    if command -v install >/dev/null 2>&1; then
        install -m 755 "${tmp_dir}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
    else
        cp "${tmp_dir}/${BIN_NAME}" "${INSTALL_DIR}/${BIN_NAME}"
        chmod 755 "${INSTALL_DIR}/${BIN_NAME}"
    fi

    log "Installed ${BIN_NAME} to ${INSTALL_DIR}/${BIN_NAME}"

    case ":${PATH}:" in
        *":${INSTALL_DIR}:"*)
            ;;
        *)
            log ""
            log "Note: '${INSTALL_DIR}' is not in your PATH."
            log "Add it to your shell profile (e.g. ~/.bashrc):"
            log "  export PATH=\"${INSTALL_DIR}:\$PATH\""
            ;;
    esac

    log ""
    log "Run 'envmgr' to launch the TUI and initialize shell integration."
}

main "$@"
