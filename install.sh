#!/usr/bin/env bash
#
# LureGuard.ai installer
#
#   curl -fsSLO https://raw.githubusercontent.com/MajdKhalaf12/LureGuard.ai/main/install.sh
#   less install.sh          # you are installing a security tool. read it.
#   sh install.sh
#
# This script deliberately does NOT install anything on your host. It checks
# what it needs, and if something is missing it tells you the exact command to
# run and stops. Installers that sudo-install packages for you are asking for
# a trust you have no way to audit mid-pipe.
#
# What it does write:
#   ~/lureguard/            the repo checkout (override with --dir)
#   ~/lureguard/.env        generated secrets, mode 0600
#   docker volumes          postgres data, wazuh state, grafana state
#
set -euo pipefail

REPO_URL="https://github.com/MajdKhalaf12/LureGuard.ai.git"
REPO_REF="${LUREGUARD_REF:-main}"
INSTALL_DIR="${LUREGUARD_DIR:-$HOME/lureguard}"
MIN_RAM_MB=2048
MIN_DISK_MB=5120

ASSUME_YES=0
DRY_RUN=0
WANT_HONEYPOTS=""
WANT_TELEGRAM=""
WANT_DEMO=""
GRAFANA_PORT=3000

# ── UI ────────────────────────────────────────────────────────────────────────
# Colour only when we are actually talking to a terminal that wants it.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
  C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'
  C_CYAN=$'\033[38;5;51m'; C_CYAN_D=$'\033[38;5;38m'
  C_BROWN=$'\033[38;5;130m'; C_BROWN_D=$'\033[38;5;94m'
  C_GREEN=$'\033[38;5;42m'; C_RED=$'\033[38;5;203m'
  C_AMBER=$'\033[38;5;214m'; C_GREY=$'\033[38;5;245m'; C_FACE=$'\033[38;5;252m'
else
  C_RESET=''; C_BOLD=''; C_DIM=''; C_CYAN=''; C_CYAN_D=''
  C_BROWN=''; C_BROWN_D=''; C_GREEN=''; C_RED=''; C_AMBER=''; C_GREY=''; C_FACE=''
fi

STAGE=0
STAGE_TOTAL=6

ui_ok()    { printf '  %s✔%s %s\n'  "$C_GREEN" "$C_RESET" "$1"; }
ui_fail()  { printf '  %s✘%s %s\n'  "$C_RED"   "$C_RESET" "$1"; }
ui_warn()  { printf '  %s!%s %s\n'  "$C_AMBER" "$C_RESET" "$1"; }
ui_info()  { printf '  %s·%s %s\n'  "$C_GREY"  "$C_RESET" "$1"; }
ui_hint()  { printf '      %s%s%s\n' "$C_GREY" "$1" "$C_RESET"; }
ui_cmd()   { printf '      %s%s%s\n' "$C_CYAN" "$1" "$C_RESET"; }

stage() {
  STAGE=$((STAGE + 1))
  printf '\n%s%s[%d/%d]%s %s%s%s\n' \
    "$C_BOLD" "$C_CYAN" "$STAGE" "$STAGE_TOTAL" "$C_RESET" "$C_BOLD" "$1" "$C_RESET"
}

banner() {
  # Rasterised from logo.png, not hand-drawn: per cell, alpha coverage picks the
  # block glyph and the cell's mean colour picks the palette entry. Coverage
  # rather than brightness because the logo is art on transparency whose wings
  # and hat sit at nearly the same brightness — a brightness ramp renders one
  # flat blob with no skull and no wings.
  #
  # Colour is quantised to the ${C_*} variables above instead of being written
  # as 24-bit escapes, and that is what keeps the NO_COLOR / TERM=dumb path
  # working: those variables expand to '' and the art prints plain. Raw escapes
  # would need sed to strip them, and banner() runs before preflight has
  # established that any external binary is on PATH.
  #
  # Regions come from saturation, not hue. The skull is desaturated blue-grey
  # (112,133,144), so it is blue-dominant exactly like the cyan wings and no hue
  # test separates the two. Measured saturation splits them with wide margin —
  # wings 0.76-0.94, hat 0.60-0.66, skull 0.22-0.25 — so the cut sits at 0.45.
  #
  # printf is a builtin; `cat` would make the banner need an external binary on
  # PATH before preflight has checked anything.
  local art="
                       ${C_CYAN}▒░                       ${C_BROWN_D}▒█             ${C_CYAN}▒▒${C_RESET}
             ${C_CYAN}░░▒▒▓▓▓█████▓            ${C_BROWN_D}▓█▓▒   ${C_BROWN}░▓███▓           ${C_CYAN}▓███████▓▓▒▒▒░░${C_RESET}
      ${C_CYAN}▒▓████████████${C_CYAN_D}████${C_CYAN}██▒          ${C_BROWN}▒███${C_BROWN_D}███${C_BROWN}████${C_BROWN_D}███░         ${C_CYAN}▒██${C_CYAN_D}███${C_CYAN}█████████████▓▒░${C_RESET}
 ${C_CYAN}░▒████████████████████████░        ${C_BROWN}░██████████${C_BROWN_D}█████        ${C_CYAN}░████████████████████████▓░${C_RESET}
     ${C_CYAN}░▒██████████${C_CYAN_D}█████${C_CYAN}██████░       ${C_BROWN}███████████${C_BROWN_D}█████▒      ${C_CYAN}░██████${C_CYAN_D}█████${C_CYAN}█████████▓░${C_RESET}
        ${C_CYAN}░█████████████████████▒░   ${C_BROWN}███████████${C_BROWN_D}███████░  ${C_CYAN}░▓█████████████████████${C_RESET}
          ${C_CYAN}███████████████████████████${C_BROWN}████████${C_BROWN_D}█████████${C_FACE}███${C_CYAN_D}███${C_CYAN}██████████████████${C_RESET}
          ${C_CYAN}░▒▒▒▒▒▒▓███████${C_FACE}███${C_BROWN_D}███████████████████████████████${C_FACE}████${C_CYAN}███████▓▒▒░░▒▒${C_RESET}
                    ${C_CYAN}▒███████████${C_FACE}████${C_BROWN_D}███████████████${C_FACE}█████${C_CYAN}███████████░${C_RESET}
                      ${C_CYAN}▒███▓▒░  ${C_FACE}▒███████████████████${C_CYAN_D}█████   ${C_CYAN}░▒▓███░${C_RESET}
                       ${C_CYAN}░▓       ${C_FACE}███████████▒▓█████${C_CYAN_D}█████▒       ${C_CYAN}▒░${C_RESET}
                                 ${C_FACE}▓████████████████████░${C_RESET}
                                       ${C_FACE}██░▒██ ▓██${C_RESET}

     ${C_BOLD}${C_CYAN}LureGuard.ai${C_RESET}   ${C_GREY}an AI security analyst for one server${C_RESET}
     ${C_GREY}Wazuh detects · the analyst explains · you decide${C_RESET}
"
  printf '%s\n' "$art"
}

die() {
  printf '\n  %s%sInstall stopped.%s %s\n\n' "$C_BOLD" "$C_RED" "$C_RESET" "$1"
  exit 1
}

# ── prompts ───────────────────────────────────────────────────────────────────
# `curl ... | sh` leaves stdin pointing at the pipe, so read from the terminal
# directly when there is one. With no terminal at all we take the defaults
# rather than hanging forever waiting for input that cannot arrive.
TTY=""
[ -e /dev/tty ] && [ -r /dev/tty ] && TTY=/dev/tty

interactive() { [ "$ASSUME_YES" != 1 ] && [ -n "$TTY" ]; }

ask_yes_no() {  # $1 question, $2 default(y/n) -> echoes y|n
  local q="$1" def="$2" ans hint
  if [ "$ASSUME_YES" = 1 ] || [ -z "$TTY" ]; then echo "$def"; return; fi
  [ "$def" = y ] && hint="Y/n" || hint="y/N"
  printf '  %s?%s %s %s[%s]%s ' "$C_CYAN" "$C_RESET" "$q" "$C_GREY" "$hint" "$C_RESET" > "$TTY"
  read -r ans < "$TTY" || ans=""
  case "${ans:-$def}" in [Yy]*) echo y ;; *) echo n ;; esac
}

ask_value() {  # $1 question, $2 default -> echoes value
  local q="$1" def="$2" ans
  if [ "$ASSUME_YES" = 1 ] || [ -z "$TTY" ]; then echo "$def"; return; fi
  if [ -n "$def" ]; then
    printf '  %s?%s %s %s[%s]%s ' "$C_CYAN" "$C_RESET" "$q" "$C_GREY" "$def" "$C_RESET" > "$TTY"
  else
    printf '  %s?%s %s ' "$C_CYAN" "$C_RESET" "$q" > "$TTY"
  fi
  read -r ans < "$TTY" || ans=""
  echo "${ans:-$def}"
}

gen_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  elif [ -r /dev/urandom ]; then
    LC_ALL=C tr -dc 'a-f0-9' < /dev/urandom | head -c 48
  else
    die "No source of randomness (need openssl or /dev/urandom) — refusing to generate weak secrets."
  fi
}

port_busy() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
  else
    return 1   # cannot tell; do not block the install on a missing tool
  fi
}

port_owner() {
  command -v lsof >/dev/null 2>&1 || { echo "unknown process"; return; }
  lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | awk 'NR==2{print $1" (pid "$2")"}'
}

# A port held by our own stack is a re-run, not a conflict. Without this the
# installer refuses to upgrade an existing install because it collides with
# itself — and the port owner reads as the Docker runtime (OrbStack, Docker
# Desktop), which tells the user nothing about what to stop.
port_is_ours() {
  docker ps --filter "publish=$1" --format '{{.Label "com.docker.compose.project"}}' 2>/dev/null \
    | grep -qi 'lureguard'
}

# ── args ──────────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes|--non-interactive) ASSUME_YES=1 ;;
    --dry-run)        DRY_RUN=1 ;;
    --dir)            INSTALL_DIR="$2"; shift ;;
    --ref)            REPO_REF="$2"; shift ;;
    --honeypots)      WANT_HONEYPOTS=y ;;
    --no-honeypots)   WANT_HONEYPOTS=n ;;
    --no-demo)        WANT_DEMO=n ;;
    -h|--help)
      printf 'LureGuard installer\n\n'
      printf '  --dir PATH        install location (default ~/lureguard)\n'
      printf '  --ref REF         git ref to install (default main)\n'
      printf '  -y, --yes         accept defaults, no prompts\n'
      printf '  --honeypots       enable Cowrie honeypots\n'
      printf '  --no-demo         skip demo data\n'
      printf '  --dry-run         show the plan, change nothing\n\n'
      exit 0 ;;
    *) die "Unknown option: $1  (try --help)" ;;
  esac
  shift
done

banner
[ "$DRY_RUN" = 1 ] && ui_warn "Dry run — nothing will be written or started." && printf '\n'

# ── 1 · preflight (hard gate) ────────────────────────────────────────────────
stage "Checking what this machine already has"

FAILED=0
need_fail() { ui_fail "$1"; shift; for l in "$@"; do ui_cmd "$l"; done; FAILED=1; }

case "$(uname -s)" in
  Linux)  OS=linux;  ui_ok "Operating system — Linux" ;;
  Darwin) OS=macos;  ui_ok "Operating system — macOS" ;;
  *) need_fail "Unsupported OS: $(uname -s). LureGuard runs on Linux or macOS." ;;
esac

if command -v docker >/dev/null 2>&1; then
  ui_ok "Docker — $(docker --version 2>/dev/null | sed 's/,.*//')"
  if docker info >/dev/null 2>&1; then
    ui_ok "Docker daemon — running"
  else
    if [ "$OS" = macos ]; then
      need_fail "Docker is installed but the daemon is not running." "open -a Docker"
    else
      need_fail "Docker is installed but the daemon is not running." \
                "sudo systemctl start docker" \
                "sudo usermod -aG docker \$USER   # then log out and back in"
    fi
  fi
else
  if [ "$OS" = macos ]; then
    need_fail "Docker is not installed." "brew install --cask docker"
  else
    need_fail "Docker is not installed." "curl -fsSL https://get.docker.com | sh"
  fi
fi

if docker compose version >/dev/null 2>&1; then
  ui_ok "Docker Compose — $(docker compose version --short 2>/dev/null)"
else
  need_fail "Docker Compose v2 is missing (the 'docker compose' subcommand)." \
            "https://docs.docker.com/compose/install/"
fi

if command -v git >/dev/null 2>&1; then
  ui_ok "git — $(git --version | awk '{print $3}')"
else
  [ "$OS" = macos ] && need_fail "git is not installed." "xcode-select --install" \
                    || need_fail "git is not installed." "sudo apt install git   # or dnf/pacman"
fi

command -v curl >/dev/null 2>&1 && ui_ok "curl — present" || need_fail "curl is not installed." "sudo apt install curl"

# Memory. ARC-1 measured the stack at ~845 MiB under sustained load, so 2 GB is
# the honest floor rather than a number picked to look modest.
if [ "$OS" = linux ]; then
  RAM_MB=$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
else
  RAM_MB=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1048576 ))
fi
if [ "$RAM_MB" -ge "$MIN_RAM_MB" ]; then
  ui_ok "Memory — ${RAM_MB} MB"
elif [ "$RAM_MB" = 0 ]; then
  ui_warn "Memory — could not determine; ${MIN_RAM_MB} MB required"
else
  need_fail "Memory — ${RAM_MB} MB, but LureGuard needs ${MIN_RAM_MB} MB (measured ~845 MB under load, plus headroom)."
fi

DISK_MB=$(df -Pm "$(dirname "$INSTALL_DIR")" 2>/dev/null | awk 'NR==2{print $4}' || echo 0)
if [ "${DISK_MB:-0}" -ge "$MIN_DISK_MB" ]; then
  ui_ok "Disk — ${DISK_MB} MB free"
else
  need_fail "Disk — ${DISK_MB} MB free, need ${MIN_DISK_MB} MB for images and data."
fi

ALREADY_RUNNING=0
for p in 8080 5432 1514 1515 55000; do
  port_busy "$p" || continue
  if port_is_ours "$p"; then
    ALREADY_RUNNING=1
  else
    need_fail "Port $p is already in use by $(port_owner "$p")." \
              "Stop it, or set a different port in docker-compose.yml before continuing."
  fi
done
if [ "$ALREADY_RUNNING" = 1 ]; then
  ui_ok "Required ports — held by an existing LureGuard stack (this is an upgrade)"
else
  ui_ok "Required ports — free"
fi

if [ "$FAILED" = 1 ]; then
  printf '\n  %s%sMissing prerequisites.%s Install what is listed above and run this again.\n' \
    "$C_BOLD" "$C_RED" "$C_RESET"
  printf '  %sThis installer will not install system packages for you — on a security\n' "$C_GREY"
  printf '  tool you should be the one deciding what touches your host.%s\n\n' "$C_RESET"
  exit 1
fi

# ── 2 · questions ─────────────────────────────────────────────────────────────
stage "Setting up your install"

INSTALL_DIR=$(ask_value "Where should LureGuard live?" "$INSTALL_DIR")

if port_busy "$GRAFANA_PORT" && ! port_is_ours "$GRAFANA_PORT"; then
  ui_warn "Port $GRAFANA_PORT is taken by $(port_owner "$GRAFANA_PORT")"
  GRAFANA_PORT=$(ask_value "Which port should the dashboard use instead?" "3001")
fi

[ -z "$WANT_DEMO" ] && WANT_DEMO=$(ask_yes_no "Load demo data so there's something to look at straight away?" y)

[ -z "$WANT_TELEGRAM" ] && WANT_TELEGRAM=$(ask_yes_no "Send alerts to Telegram?" n)
TG_TOKEN=""; TG_CHAT=""
if [ "$WANT_TELEGRAM" = y ]; then
  interactive && ui_hint "Create a bot with @BotFather, then message it once so it can reply to you."
  TG_TOKEN=$(ask_value "  Bot token" "")
  TG_CHAT=$(ask_value "  Chat ID" "")
  [ -z "$TG_TOKEN" ] || [ -z "$TG_CHAT" ] && { ui_warn "Telegram left unconfigured — you can fill it in later in .env"; WANT_TELEGRAM=n; }
fi

if [ -z "$WANT_HONEYPOTS" ]; then
  if interactive; then
    ui_hint "Honeypots are fake SSH services that record attackers. They listen on"
    ui_hint "ports 2222 and 2223 — only enable these if this host is exposed."
  fi
  WANT_HONEYPOTS=$(ask_yes_no "Enable the Cowrie honeypots?" n)
fi

if [ "$DRY_RUN" = 1 ]; then
  printf '\n  %sPlan:%s clone %s@%s -> %s, generate secrets, start %s services%s\n' \
    "$C_BOLD" "$C_RESET" "$REPO_URL" "$REPO_REF" "$INSTALL_DIR" \
    "$([ "$WANT_HONEYPOTS" = y ] && echo 6 || echo 4)" "$C_RESET"
  printf '  %sdemo=%s telegram=%s honeypots=%s grafana_port=%s%s\n\n' \
    "$C_GREY" "$WANT_DEMO" "$WANT_TELEGRAM" "$WANT_HONEYPOTS" "$GRAFANA_PORT" "$C_RESET"
  exit 0
fi

# ── 3 · fetch ─────────────────────────────────────────────────────────────────
stage "Fetching LureGuard"

if [ -d "$INSTALL_DIR/.git" ]; then
  ui_info "Existing install found — updating"
  git -C "$INSTALL_DIR" fetch --depth 1 origin "$REPO_REF" --quiet
  git -C "$INSTALL_DIR" checkout --quiet FETCH_HEAD
else
  [ -e "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ] && \
    die "$INSTALL_DIR exists and is not a LureGuard checkout. Move it, or pass --dir."
  git clone --depth 1 --branch "$REPO_REF" --quiet "$REPO_URL" "$INSTALL_DIR" \
    || die "Clone failed. Check your network, or that '$REPO_REF' exists."
fi
cd "$INSTALL_DIR"
# Provenance the user can check against the repo. Release tarballs with a
# SHA-256 manifest are the stronger form of this; the commit is what exists today.
ui_ok "Source — $(git rev-parse --short HEAD) on $REPO_REF"

# ── 4 · configure ─────────────────────────────────────────────────────────────
stage "Generating credentials"

if [ -f .env ]; then
  ui_info "Keeping the .env already here (delete it to regenerate secrets)"
else
  GRAFANA_PW=$(gen_secret | cut -c1-20)
  cat > .env <<EOF
# Generated by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Every secret below is unique to this install.

INGEST_TOKEN=$(gen_secret)
ADMIN_TOKEN=$(gen_secret)

GRAFANA_ADMIN_PASSWORD=${GRAFANA_PW}
GRAFANA_PORT=${GRAFANA_PORT}

TELEGRAM_BOT_TOKEN=${TG_TOKEN}
TELEGRAM_CHAT_ID=${TG_CHAT}

WAZUH_API_URL=https://localhost:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=$(gen_secret | cut -c1-24)
WAZUH_API_VERIFY_SSL=false

# Optional threat intel — enrichment tools warn if unset.
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
EOF
  chmod 600 .env
  ui_ok "Wrote .env with generated secrets (mode 0600)"
  ui_ok "Dashboard password — ${C_BOLD}${GRAFANA_PW}${C_RESET}"
fi

# ── 5 · start ─────────────────────────────────────────────────────────────────
stage "Starting services"

COMPOSE_ARGS=""
[ "$WANT_HONEYPOTS" = y ] && COMPOSE_ARGS="--profile honeypots"

ui_info "Pulling images (first run downloads ~1.5 GB)"
# shellcheck disable=SC2086
docker compose $COMPOSE_ARGS pull --quiet 2>/dev/null || true
# shellcheck disable=SC2086
docker compose $COMPOSE_ARGS up -d || die "Services failed to start. Logs: docker compose logs"

printf '  %s·%s Waiting for services to become healthy' "$C_GREY" "$C_RESET"
READY=0
for _ in $(seq 1 60); do
  if curl -fsS "http://localhost:8080/health" >/dev/null 2>&1; then READY=1; break; fi
  printf '.'
  sleep 2
done
printf '\n'
[ "$READY" = 1 ] && ui_ok "Core API — healthy" \
                 || { ui_fail "Core API did not come up within 2 minutes"; ui_cmd "docker compose logs lureguard-core"; }

curl -fsS "http://localhost:${GRAFANA_PORT}/api/health" >/dev/null 2>&1 \
  && ui_ok "Dashboard — healthy" || ui_warn "Dashboard still starting"

# ── 6 · demo data ─────────────────────────────────────────────────────────────
stage "Finishing up"

if [ "$WANT_DEMO" = y ] && [ "$READY" = 1 ]; then
  if docker compose exec -T lureguard-core python -c \
       "import asyncio; from demo_seed import load_demo; print(asyncio.run(load_demo()))" >/dev/null 2>&1; then
    ui_ok "Demo data loaded — 500 events across 4 channels"
  else
    ui_warn "Demo data did not load; the stack is fine. Retry with: make demo"
  fi
else
  ui_info "No demo data — the dashboard stays empty until real alerts arrive"
fi

printf '\n%s  ─────────────────────────────────────────────────────────%s\n' "$C_GREY" "$C_RESET"
printf '  %s%sLureGuard is running.%s\n\n' "$C_BOLD" "$C_GREEN" "$C_RESET"
printf '    Dashboard   %shttp://localhost:%s%s\n' "$C_CYAN" "$GRAFANA_PORT" "$C_RESET"
printf '    Login       %sadmin%s / the password shown above (also in .env)\n' "$C_BOLD" "$C_RESET"
printf '    Installed   %s%s%s\n\n' "$C_GREY" "$INSTALL_DIR" "$C_RESET"
printf '  Next:\n'
printf '    %scd %s && docker compose logs -f%s   watch it work\n' "$C_CYAN" "$INSTALL_DIR" "$C_RESET"
[ "$WANT_HONEYPOTS" = y ] && \
printf '    %sHoneypots are live on 2222/2223%s — anything that connects is recorded\n' "$C_AMBER" "$C_RESET"
printf '\n'
