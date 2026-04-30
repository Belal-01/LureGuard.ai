#!/usr/bin/env bash
set -euo pipefail

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║          LureGuard.ai — Installer            ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# ── Create secrets dir ────────────────────────────────────
mkdir -p secrets
chmod 700 secrets

# ── DB password ───────────────────────────────────────────
if [ ! -f secrets/db_password.txt ]; then
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/db_password.txt
    chmod 600 secrets/db_password.txt
    echo "✅ DB password generated"
fi

# ── Admin token ───────────────────────────────────────────
if [ ! -f secrets/admin_token.txt ]; then
    python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/admin_token.txt
    chmod 600 secrets/admin_token.txt
    echo "✅ Admin token generated"
fi

# ── Telegram token ────────────────────────────────────────
echo ""
read -rp "🤖 Telegram Bot Token (leave blank to skip): " TG_TOKEN
if [ -n "$TG_TOKEN" ]; then
    echo "$TG_TOKEN" > secrets/telegram_token.txt
    chmod 600 secrets/telegram_token.txt
    echo "✅ Telegram token saved"
else
    echo "dummy_token" > secrets/telegram_token.txt
    chmod 600 secrets/telegram_token.txt
    echo "⚠️  Telegram disabled — using dummy token"
fi

# ── LLM Provider ─────────────────────────────────────────
echo ""
echo "🧬 Choose LLM Provider:"
echo "  1) Ollama (local — default, needs 8GB RAM)"
echo "  2) OpenAI (GPT-4o-mini)"
echo "  3) Anthropic (Claude 3.5 Haiku)"
echo "  4) OpenAI-Compatible (Groq / OpenRouter / vLLM)"
echo "  5) Disabled (no summarization)"
read -rp "Choice [1-5]: " LLM_CHOICE

case "$LLM_CHOICE" in
    1|"")
        LLM_PROVIDER="ollama"
        LLM_MODEL="llama3:8b-q4_K_M"
        LLM_BASE_URL="http://ollama:11434"
        echo "dummy" > secrets/llm_api_key.txt
        COMPOSE_CMD="docker compose --profile local-llm up -d"
        ;;
    2)
        LLM_PROVIDER="openai"
        LLM_MODEL="gpt-4o-mini"
        LLM_BASE_URL="https://api.openai.com"
        read -rp "  OpenAI API Key: " API_KEY
        echo "$API_KEY" > secrets/llm_api_key.txt
        COMPOSE_CMD="docker compose up -d"
        ;;
    3)
        LLM_PROVIDER="anthropic"
        LLM_MODEL="claude-3-5-haiku-20241022"
        LLM_BASE_URL="https://api.anthropic.com"
        read -rp "  Anthropic API Key: " API_KEY
        echo "$API_KEY" > secrets/llm_api_key.txt
        COMPOSE_CMD="docker compose up -d"
        ;;
    4)
        LLM_PROVIDER="openai_compatible"
        read -rp "  Base URL (e.g. https://openrouter.ai/api): " LLM_BASE_URL
        read -rp "  Model name: " LLM_MODEL
        read -rp "  API Key: " API_KEY
        echo "$API_KEY" > secrets/llm_api_key.txt
        COMPOSE_CMD="docker compose up -d"
        ;;
    5)
        LLM_PROVIDER="disabled"
        LLM_MODEL=""
        LLM_BASE_URL=""
        echo "disabled" > secrets/llm_api_key.txt
        COMPOSE_CMD="docker compose up -d"
        ;;
    *)
        echo "❌ Invalid choice"; exit 1 ;;
esac

chmod 600 secrets/llm_api_key.txt
echo "✅ LLM provider: $LLM_PROVIDER ($LLM_MODEL)"

# ── Write core.yaml ───────────────────────────────────────
cat > config/core.yaml << YAML
thresholds:
  t1: 0.40
  t2: 0.70

llm:
  provider: ${LLM_PROVIDER}
  model: ${LLM_MODEL}
  base_url: ${LLM_BASE_URL}
  timeout_seconds: 60
  max_tokens: 512

cowrie_profiles:
  dev-server:
    host: cowrie-dev
    port: 2222
  db-server:
    host: cowrie-db
    port: 2223

window_seconds: 300
tick_interval_seconds: 2
dnat_ttl_minutes: 60
YAML

echo ""
echo "✅ config/core.yaml written"
echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║  Setup complete! Run:                        ║"
echo "║  ${COMPOSE_CMD}"
echo "╚══════════════════════════════════════════════╝"
