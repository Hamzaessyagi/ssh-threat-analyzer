#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  SSH Threat Analyzer - Main Pipeline
#  Usage: ./run.sh <path_to_auth.log>
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ─── Colors ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/output"
SCRIPTS_DIR="$SCRIPT_DIR/scripts"

# ─── Banner ────────────────────────────────────────────────────
print_banner() {
    echo -e "${BLUE}"
    echo "  ███████╗███████╗██╗  ██╗    ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗"
    echo "  ██╔════╝██╔════╝██║  ██║       ██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝"
    echo "  ███████╗███████╗███████║       ██║   ███████║██████╔╝█████╗  ███████║   ██║   "
    echo "  ╚════██║╚════██║██╔══██║       ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   "
    echo "  ███████║███████║██║  ██║       ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   "
    echo "  ╚══════╝╚══════╝╚═╝  ╚═╝       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   "
    echo -e "  ${CYAN}SSH Auth Log Analyzer | Python + Bash Pipeline${NC}"
    echo ""
}

# ─── Helpers ───────────────────────────────────────────────────
step()  { echo -e "\n${CYAN}[STEP]${NC} ${BOLD}$1${NC}"; }
ok()    { echo -e "${GREEN}[  OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail()  { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }

check_deps() {
    step "Checking dependencies..."
    command -v python3 >/dev/null || fail "python3 not found"
    ok "python3 found: $(python3 --version)"

    python3 -c "import matplotlib" 2>/dev/null && ok "matplotlib OK" || {
        warn "matplotlib not found — installing..."
        pip install matplotlib numpy --quiet --break-system-packages 2>/dev/null \
            || pip install matplotlib numpy --quiet || fail "Could not install matplotlib"
        ok "matplotlib installed"
    }
}

validate_input() {
    local logfile="$1"
    [[ -f "$logfile" ]] || fail "File not found: $logfile"
    local lines; lines=$(wc -l < "$logfile")
    ok "Log file: $logfile ($lines lines)"
}

run_quick_bash_stats() {
    local logfile="$1"
    step "Quick Bash pre-analysis..."
    local failed; failed=$(grep -c "Failed password" "$logfile" 2>/dev/null || echo 0)
    local invalid; invalid=$(grep -c "Invalid user" "$logfile" 2>/dev/null || echo 0)
    local accepted; accepted=$(grep -c "Accepted" "$logfile" 2>/dev/null || echo 0)
    local unique_ips; unique_ips=$(grep -oP 'from \K[\d.]+' "$logfile" 2>/dev/null | sort -u | wc -l || echo 0)

    echo -e "  ${YELLOW}Failed passwords :${NC} $failed"
    echo -e "  ${YELLOW}Invalid users    :${NC} $invalid"
    echo -e "  ${GREEN}Accepted logins  :${NC} $accepted"
    echo -e "  ${CYAN}Unique IPs       :${NC} $unique_ips"

    # Most common IP (quick)
    local top_ip; top_ip=$(grep -oP 'from \K[\d.]+' "$logfile" 2>/dev/null \
        | sort | uniq -c | sort -rn | head -1 || echo "N/A")
    echo -e "  ${RED}Top attacker     :${NC} $top_ip"
}

main() {
    print_banner

    # ── Argument check ──────────────────────────────────────────
    if [[ $# -lt 1 ]]; then
        echo -e "Usage: ${BOLD}./run.sh <auth.log> [--geo]${NC}"
        echo "  --geo   Also run GeoIP lookup (requires internet, ~1 min for top 20 IPs)"
        exit 1
    fi

    local logfile="$1"
    local do_geo="${2:-}"
    mkdir -p "$OUTPUT_DIR"

    # ── Steps ───────────────────────────────────────────────────
    check_deps
    validate_input "$logfile"
    run_quick_bash_stats "$logfile"

    step "Running Python deep analysis..."
    python3 "$SCRIPTS_DIR/analyze.py" "$logfile" -o "$OUTPUT_DIR"

    step "Generating visualizations..."
    python3 "$SCRIPTS_DIR/visualize.py" "$OUTPUT_DIR/analysis.json" -o "$OUTPUT_DIR/dashboard.png"

    if [[ "$do_geo" == "--geo" ]]; then
        step "Running GeoIP lookup (top 20 IPs)..."
        python3 "$SCRIPTS_DIR/geoip.py" "$OUTPUT_DIR/analysis.json" -o "$OUTPUT_DIR/analysis_geo.json"
    fi

    # ── Final summary ───────────────────────────────────────────
    echo ""
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  ✅  ANALYSIS COMPLETE!${NC}"
    echo -e "${GREEN}${BOLD}═══════════════════════════════════════${NC}"
    echo ""
    echo -e "  📊 Dashboard   : ${CYAN}$OUTPUT_DIR/dashboard.png${NC}"
    echo -e "  📋 JSON data   : ${CYAN}$OUTPUT_DIR/analysis.json${NC}"
    [[ "$do_geo" == "--geo" ]] && \
    echo -e "  🌍 GeoIP data  : ${CYAN}$OUTPUT_DIR/analysis_geo.json${NC}"
    echo ""
    echo -e "  ${YELLOW}Tip: Open dashboard.png with:${NC}"
    echo -e "  ${BOLD}xdg-open $OUTPUT_DIR/dashboard.png${NC}"
    echo ""
}

main "$@"
