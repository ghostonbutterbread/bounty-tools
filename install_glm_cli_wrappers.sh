#!/usr/bin/env bash
# Install lightweight GLM wrappers for Claude Code and Codex.

set -euo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
CONFIG_DIR="${ZAI_CONFIG_DIR:-$HOME/.config/zai}"
KEY_FILE="${ZAI_KEY_FILE:-$CONFIG_DIR/api_key}"

usage() {
    cat <<'USAGE'
Usage:
  install_glm_cli_wrappers.sh install
  install_glm_cli_wrappers.sh set-key
  install_glm_cli_wrappers.sh status
  install_glm_cli_wrappers.sh helper

Commands:
  install   Install claude-glm and codex-glm into ~/.local/bin
  set-key   Prompt for a Z.ai API key and store it in ~/.config/zai/api_key
  status    Show detected local tools and wrapper/key status
  helper    Run the upstream Z.ai helper with npx

The wrappers keep the API key out of shell aliases and history by reading it
from ~/.config/zai/api_key at runtime.
USAGE
}

install_wrappers() {
    mkdir -p "$BIN_DIR" "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    cat >"$BIN_DIR/claude-glm" <<'EOF'
#!/usr/bin/env bash
# claude-glm - Run Claude Code with Z.ai GLM backend

set -euo pipefail

KEY_FILE="${ZAI_KEY_FILE:-$HOME/.config/zai/api_key}"

if [[ ! -f "$KEY_FILE" ]]; then
    echo "Z.ai API key not found at $KEY_FILE" >&2
    echo "" >&2
    echo "Store your GLM Coding Plan API key (one-time):" >&2
    echo "  mkdir -p ~/.config/zai && chmod 700 ~/.config/zai" >&2
    echo "  printf '%s\n' 'zai-key-here' > ~/.config/zai/api_key" >&2
    echo "  chmod 600 ~/.config/zai/api_key" >&2
    echo "" >&2
    echo "Get your key at: https://z.ai/manage-apikey/apikey-list" >&2
    exit 1
fi

if [[ "$(stat -c '%a' "$KEY_FILE" 2>/dev/null || stat -f '%Lp' "$KEY_FILE")" != "600" ]]; then
    echo "Refusing to use $KEY_FILE because it is not chmod 600" >&2
    echo "Fix with: chmod 600 ~/.config/zai/api_key" >&2
    exit 1
fi

if ! command -v claude >/dev/null 2>&1; then
    echo "claude was not found on PATH" >&2
    exit 1
fi

ZAI_KEY="$(tr -d '\r\n' <"$KEY_FILE")"

if [[ -z "${ZAI_KEY// }" ]]; then
    echo "Z.ai API key file is empty: $KEY_FILE" >&2
    exit 1
fi

export ANTHROPIC_BASE_URL="https://api.z.ai/api/anthropic"
export ANTHROPIC_AUTH_TOKEN="$ZAI_KEY"
export ANTHROPIC_DEFAULT_SONNET_MODEL="${ANTHROPIC_DEFAULT_SONNET_MODEL:-glm-5.2[1m]}"
export ANTHROPIC_DEFAULT_OPUS_MODEL="${ANTHROPIC_DEFAULT_OPUS_MODEL:-glm-5.2[1m]}"
export ANTHROPIC_DEFAULT_HAIKU_MODEL="${ANTHROPIC_DEFAULT_HAIKU_MODEL:-glm-4.7}"
export API_TIMEOUT_MS="${API_TIMEOUT_MS:-3000000}"

exec claude "$@"
EOF

    cat >"$BIN_DIR/codex-glm" <<'EOF'
#!/usr/bin/env bash
# codex-glm - Run Codex CLI with Z.ai GLM backend

set -euo pipefail

KEY_FILE="${ZAI_KEY_FILE:-$HOME/.config/zai/api_key}"

if [[ ! -f "$KEY_FILE" ]]; then
    echo "Z.ai API key not found at $KEY_FILE" >&2
    echo "" >&2
    echo "Store your GLM Coding Plan API key (one-time):" >&2
    echo "  mkdir -p ~/.config/zai && chmod 700 ~/.config/zai" >&2
    echo "  printf '%s\n' 'zai-key-here' > ~/.config/zai/api_key" >&2
    echo "  chmod 600 ~/.config/zai/api_key" >&2
    echo "" >&2
    echo "Get your key at: https://z.ai/manage-apikey/apikey-list" >&2
    exit 1
fi

if [[ "$(stat -c '%a' "$KEY_FILE" 2>/dev/null || stat -f '%Lp' "$KEY_FILE")" != "600" ]]; then
    echo "Refusing to use $KEY_FILE because it is not chmod 600" >&2
    echo "Fix with: chmod 600 ~/.config/zai/api_key" >&2
    exit 1
fi

if ! command -v codex >/dev/null 2>&1; then
    echo "codex was not found on PATH" >&2
    exit 1
fi

ZAI_KEY="$(tr -d '\r\n' <"$KEY_FILE")"

if [[ -z "${ZAI_KEY// }" ]]; then
    echo "Z.ai API key file is empty: $KEY_FILE" >&2
    exit 1
fi

export OPENAI_BASE_URL="https://api.z.ai/api/coding/paas/v4"
export OPENAI_API_KEY="$ZAI_KEY"

exec codex "$@"
EOF

    chmod 755 "$BIN_DIR/claude-glm" "$BIN_DIR/codex-glm"
    echo "Installed:"
    echo "  $BIN_DIR/claude-glm"
    echo "  $BIN_DIR/codex-glm"
}

set_key() {
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    printf "Z.ai API key: " >&2
    read -rs key
    printf "\n" >&2

    if [[ -z "${key// }" ]]; then
        echo "Refusing to store an empty key" >&2
        exit 1
    fi

    umask 077
    printf '%s\n' "$key" >"$KEY_FILE"
    chmod 600 "$KEY_FILE"
    echo "Stored key at $KEY_FILE"
}

status() {
    echo "Tool status:"
    for tool in git node npm npx claude codex; do
        if command -v "$tool" >/dev/null 2>&1; then
            printf "  %-10s %s\n" "$tool" "$(command -v "$tool")"
        else
            printf "  %-10s missing\n" "$tool"
        fi
    done

    echo ""
    echo "Wrapper status:"
    for wrapper in claude-glm codex-glm; do
        if [[ -x "$BIN_DIR/$wrapper" ]]; then
            printf "  %-10s installed at %s\n" "$wrapper" "$BIN_DIR/$wrapper"
        else
            printf "  %-10s missing\n" "$wrapper"
        fi
    done

    echo ""
    if [[ -f "$KEY_FILE" ]]; then
        echo "Key file: present at $KEY_FILE"
        echo "Mode: $(stat -c '%a' "$KEY_FILE" 2>/dev/null || stat -f '%Lp' "$KEY_FILE")"
    else
        echo "Key file: missing at $KEY_FILE"
    fi
}

run_helper() {
    exec npx @z_ai/coding-helper
}

case "${1:-}" in
    install)
        install_wrappers
        ;;
    set-key)
        set_key
        ;;
    status)
        status
        ;;
    helper)
        run_helper
        ;;
    -h|--help|help|"")
        usage
        ;;
    *)
        echo "Unknown command: $1" >&2
        usage >&2
        exit 2
        ;;
esac
