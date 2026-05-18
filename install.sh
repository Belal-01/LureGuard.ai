#!/usr/bin/env bash
# ============================================================
#  LureGuard.ai — Installer (Sprint 1)
#  Covers:
#    ✅ Wazuh Manager in Docker (wazuh-manager:4.14.5)
#    ✅ Wazuh Agent on Ubuntu target VM
#    ✅ log sources: auth.log, syslog/journald, FIM
#    ✅ integratord → lureguard-core:8080 (Core not built yet)
#
#  Not yet covered:
#    ○ LureGuard Core (FastAPI)   — Sprint 2
#    ○ PostgreSQL                 — Sprint 2
#    ○ Cowrie x2                  — Sprint 3
#    ○ Grafana                    — Sprint 3
#    ○ LLM / Gemini               — Sprint 3
#    ○ ML model                   — Sprint 2-3
#
#  Usage:
#    ./install.sh          normal
#    ./install.sh -v       verbose (shows every VM command + result)
#
#  Requirements (Mac/Linux host):
#    - Docker Desktop running
#    - python3, ssh, scp available
#  Windows: run inside WSL2
# ============================================================
set -euo pipefail

# ── Colors & helpers ──────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'; BOLD='\033[1m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()    { echo -e "\n${BOLD}── $* ──${NC}"; }

# ── Verbose flag ──────────────────────────────────────────
VERBOSE=false
for arg in "$@"; do
    case $arg in -v|--verbose) VERBOSE=true ;; esac
done

# vm_sudo — run a sudo command on the VM
# with -v: prints the command label and exit code
vm_sudo() {
    local label="$1"; shift
    if $VERBOSE; then
        echo -e "${BLUE}[CMD]${NC}   $label"
        OUTPUT=$(ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR \
            "${VM_USER}@${VM_IP}" \
            "echo '${VM_PASS}' | sudo -S bash -c $(printf '%q' "$*") 2>/dev/null" 2>&1) \
            && RC=0 || RC=$?
        [ -n "$OUTPUT" ] && echo "$OUTPUT" | sed 's/^/        /'
        [ $RC -eq 0 ] \
            && echo -e "${GREEN}[EXIT]${NC}  0 (ok)" \
            || echo -e "${RED}[EXIT]${NC}  $RC (failed)"
        return $RC
    else
        ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR \
            "${VM_USER}@${VM_IP}" \
            "echo '${VM_PASS}' | sudo -S bash -c $(printf '%q' "$*") 2>/dev/null"
    fi
}

# vm_ssh — run a plain (non-sudo) command on the VM, capture output cleanly
vm_ssh() {
    ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR \
        "${VM_USER}@${VM_IP}" "$@" 2>/dev/null | tr -d '\r\n'
}

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║          LureGuard.ai — Installer            ║${NC}"
echo -e "${BOLD}║          Sprint 1: Wazuh Layer               ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── Preflight ─────────────────────────────────────────────
step "Checking prerequisites"

command -v docker  >/dev/null 2>&1 || error "Docker not found. Install Docker Desktop first."
command -v python3 >/dev/null 2>&1 || error "python3 not found."
command -v ssh     >/dev/null 2>&1 || error "ssh not found."
command -v scp     >/dev/null 2>&1 || error "scp not found."
docker info >/dev/null 2>&1        || error "Docker is not running. Start Docker Desktop first."
success "Docker is running"

[ -f wazuh/ossec.conf ]       || error "wazuh/ossec.conf not found. Are you in the repo root?"
[ -f wazuh/local_rules.xml ]  || error "wazuh/local_rules.xml not found."
[ -f wazuh/agent-ossec.conf ] || error "wazuh/agent-ossec.conf not found."
[ -f wazuh/integrations/custom-lureguard.py ] || error "wazuh/integrations/custom-lureguard.py not found."
[ -f wazuh/integrations/custom-lureguard ] || error "wazuh/integrations/custom-lureguard not found."
[ -f docker-compose.yml ]     || error "docker-compose.yml not found."
chmod +x wazuh/integrations/custom-lureguard scripts/setup_venv.sh scripts/ensure_ml_artifacts.sh 2>/dev/null || true
success "Repo files OK"

# ── Python venv (repo root) ─────────────────────────────────
step "Setting up Python virtualenv at .venv/"
bash scripts/setup_venv.sh

# ── ML model artifacts (ml/models) ────────────────────────
step "Ensuring ML model artifacts"
bash scripts/ensure_ml_artifacts.sh

# ── Secrets ───────────────────────────────────────────────
step "Generating secrets"

mkdir -p secrets && chmod 700 secrets
gen_secret() { python3 -c "import secrets; print(secrets.token_urlsafe(32))"; }

if [ ! -f secrets/db_password.txt ]; then
    gen_secret > secrets/db_password.txt && chmod 600 secrets/db_password.txt
    success "DB password generated"
else
    info "DB password already exists — skipping"
fi

if [ ! -f secrets/admin_token.txt ]; then
    gen_secret > secrets/admin_token.txt && chmod 600 secrets/admin_token.txt
    success "Admin token generated"
else
    info "Admin token already exists — skipping"
fi

# Placeholders — filled in later sprints
[ -f secrets/telegram_token.txt ] || { echo "dummy_token" > secrets/telegram_token.txt; chmod 600 secrets/telegram_token.txt; info "Telegram token → dummy (Sprint 3)"; }
[ -f secrets/llm_api_key.txt ]    || { echo "dummy_key"   > secrets/llm_api_key.txt;    chmod 600 secrets/llm_api_key.txt;    info "LLM API key → dummy (Sprint 3)"; }

# ── config/core.yaml ──────────────────────────────────────
step "Writing config/core.yaml"
mkdir -p config
if [ ! -f config/core.yaml ]; then
cat > config/core.yaml << 'YAML'
# LureGuard Core — Sprint 1 (only thresholds active)

thresholds:
  t1: 0.40
  t2: 0.70

# ── LLM (Sprint 3 — بلال) ────────────────────────────────
# llm:
#   provider: openai_compatible
#   model: "gemini-1.5-flash"
#   base_url: "https://generativelanguage.googleapis.com/v1beta/openai"
#   timeout_seconds: 60
#   max_tokens: 512

# ── Cowrie profiles (Sprint 3 — بلال) ───────────────────
# cowrie_profiles:
#   dev-server:
#     host: cowrie-dev
#     port: 2222
#   db-server:
#     host: cowrie-db
#     port: 2223

# ── Feature extraction (Sprint 2 — علي) ─────────────────
window_seconds: 300
tick_interval_seconds: 10

# ── Enforcement (Sprint 2 — مجد) ────────────────────────
dnat_ttl_minutes: 60
YAML
    success "config/core.yaml written"
else
    info "config/core.yaml already exists — skipping"
fi

# ── Start Wazuh Manager ───────────────────────────────────
step "Starting Wazuh Manager"
docker compose up -d
docker compose restart wazuh-manager >/dev/null 2>&1 || true
info "Waiting 30s for Wazuh Manager to be healthy..."
sleep 30
INTEGRATORD_ERR=$(docker exec wazuh-manager grep -c "Unable to enable integration for: 'lureguard'" /var/ossec/logs/ossec.log 2>/dev/null || echo 0)
if docker exec wazuh-manager test -x /var/ossec/integrations/lureguard.py 2>/dev/null; then
    success "Wazuh lureguard integration script mounted"
else
    warn "lureguard integration not found in container — run: docker compose up -d --force-recreate"
fi
DB_STATUS=$(docker exec wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep "wazuh-db" || true)
echo "$DB_STATUS" | grep -q "is running" \
    && success "Wazuh Manager is healthy" \
    || error "Wazuh Manager did not start. Run: docker logs wazuh-manager --tail 30"

# ── VM credentials ────────────────────────────────────────
step "Ubuntu target VM — Wazuh Agent setup"
echo ""
read -rp  "  Ubuntu VM IP address: "       VM_IP
read -rp  "  SSH user (default: ubuntu): " VM_USER
VM_USER=${VM_USER:-ubuntu}
read -rsp "  VM sudo password: "           VM_PASS
echo ""

# Test SSH
info "Testing SSH to ${VM_USER}@${VM_IP}..."
ssh -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=5 \
    "${VM_USER}@${VM_IP}" "echo ok" >/dev/null 2>&1 \
    || error "Cannot connect to ${VM_USER}@${VM_IP}. Check IP and SSH."
success "SSH OK"

# Test sudo
vm_sudo "test sudo" "echo ok" >/dev/null 2>&1 \
    || error "Sudo failed. Check password and sudo access."
success "Sudo OK"

# ── Manager IP — detect on this machine directly ──────────
MANAGER_IP=""
for iface in en0 en1 eth0 ens33 ens3 wlan0; do
    IP=$(ipconfig getifaddr "$iface" 2>/dev/null \
        || ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 \
        || true)
    if [ -n "$IP" ]; then MANAGER_IP="$IP"; break; fi
done
[ -z "$MANAGER_IP" ] && read -rp "  Your machine's IP (manager address for agent): " MANAGER_IP
info "Manager IP: $MANAGER_IP"

# ── Install Wazuh Agent if missing ────────────────────────
AGENT_INSTALLED=$(vm_ssh "dpkg -l wazuh-agent 2>/dev/null | grep -c '^ii' || echo 0")
if [ "$AGENT_INSTALLED" = "0" ]; then
    info "Installing Wazuh Agent 4.14.5..."
    vm_sudo "add wazuh GPG key" \
        "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg"
    vm_sudo "add wazuh apt repo" \
        "echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | tee /etc/apt/sources.list.d/wazuh.list > /dev/null"
    vm_sudo "apt-get update" "apt-get update -qq"
    vm_sudo "apt-get install wazuh-agent" "apt-get install -y wazuh-agent=4.14.5-1"
    success "Wazuh Agent installed"
else
    AGENT_VER=$(vm_ssh "dpkg -l wazuh-agent 2>/dev/null | awk '/^ii/{print \$3}'" || echo "?")
    success "Wazuh Agent already installed ($AGENT_VER)"
fi

# ── Deploy agent ossec.conf via scp ───────────────────────
# scp is reliable — no heredoc, no pipe, no tee issues
info "Deploying agent config (manager → $MANAGER_IP)..."
sed "s/__WAZUH_MANAGER_IP__/${MANAGER_IP}/g" wazuh/agent-ossec.conf > /tmp/lureguard-agent-ossec.conf
scp -o StrictHostKeyChecking=no -o LogLevel=ERROR \
    /tmp/lureguard-agent-ossec.conf "${VM_USER}@${VM_IP}:/tmp/ossec.conf"
vm_sudo "install ossec.conf" "cp /tmp/ossec.conf /var/ossec/etc/ossec.conf && chmod 640 /var/ossec/etc/ossec.conf && chown root:wazuh /var/ossec/etc/ossec.conf"
$VERBOSE && echo -e "${GREEN}[EXIT]${NC}  0 (ok)" || true
success "Agent ossec.conf deployed"

# ── Register agent ────────────────────────────────────────
step "Registering agent with Wazuh Manager"

EXISTING=$(docker exec wazuh-manager bash -c \
    'grep -c "^001 " /var/ossec/etc/client.keys 2>/dev/null || echo 0')

if [ "$EXISTING" -gt 0 ]; then
    success "Agent 001 already registered — skipping"
else
    info "Registering agent 'ubuntu-target' (ID 001)..."
    docker exec wazuh-manager bash -c \
        '/var/ossec/bin/manage_agents -a 0.0.0.0 -n ubuntu-target -i 001' \
        >/dev/null 2>&1 || true
    sleep 1
    success "Agent registered"
fi

# Extract the full key line from client.keys and base64-encode it
FULL_KEY=$(docker exec wazuh-manager bash -c \
    "grep '^001 ' /var/ossec/etc/client.keys | tr -d '\n' | base64 | tr -d '\n'")
[ -n "$FULL_KEY" ] || error "Failed to build agent key. Check client.keys in the manager."
info "Agent key extracted"

# ── Import key on VM ──────────────────────────────────────
info "Importing key on VM..."
vm_sudo "import agent key" \
    "printf 'I\n${FULL_KEY}\ny\nQ\n' | /var/ossec/bin/manage_agents"

info "Enabling and restarting agent..."
vm_sudo "systemctl enable wazuh-agent" "systemctl enable wazuh-agent"
vm_sudo "systemctl restart wazuh-agent" "systemctl restart wazuh-agent"
sleep 5
STATUS=$(vm_ssh "systemctl is-active wazuh-agent || true")
[ "$STATUS" = "active" ] \
    && success "Agent service is active" \
    || warn "Agent service status: $STATUS — check: sudo systemctl status wazuh-agent"

# ── Verify from manager ───────────────────────────────────
step "Verifying agent connection"
info "Waiting 20s for agent handshake..."
sleep 20

AGENT_STATUS=$(docker exec wazuh-manager \
    /var/ossec/bin/agent_control -l 2>/dev/null | grep "ubuntu-target" || true)

if echo "$AGENT_STATUS" | grep -q "Active"; then
    success "Agent is Active — pipeline is working ✓"
elif echo "$AGENT_STATUS" | grep -q "Unknown"; then
    warn "Agent shows Unknown — wait 30s then run:"
    warn "  docker exec -it wazuh-manager /var/ossec/bin/agent_control -l"
else
    warn "Could not confirm status. Run:"
    warn "  docker exec -it wazuh-manager /var/ossec/bin/agent_control -l"
fi

# ── Done ──────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  LureGuard Sprint 1 — setup complete                 ║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}  Wazuh Manager  → running (docker compose up -d)     ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  Agent VM       → ${VM_IP}                          ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}  integratord    → POST Core :8080/wazuh/event         ${BOLD}║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}  Start Core:                                         ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    make core                                          ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    # or: cd core && PYTHONPATH=.. uvicorn main:app   ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}       --host 0.0.0.0 --port 8080                     ${BOLD}║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}  Test:                                               ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    ssh wronguser@${VM_IP}                           ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    → uvicorn shows POST /wazuh/event                 ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}    docker exec -it wazuh-manager \\                   ${BOLD}║${NC}"
echo -e "${BOLD}║${NC}      tail -f /var/ossec/logs/alerts/alerts.json      ${BOLD}║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════╝${NC}"
echo ""