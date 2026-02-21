#!/usr/bin/env bash
# ─── SSH Threat Analyzer - Docker Runner ───────────────────────
# Usage: ./docker-run.sh auth.log.1

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
BOLD='\033[1m'; NC='\033[0m'

LOGFILE="${1:-}"

if [[ -z "$LOGFILE" ]]; then
    echo -e "${RED}Usage: ./docker-run.sh <auth.log>${NC}"
    exit 1
fi

[[ ! -f "$LOGFILE" ]] && echo -e "${RED}[FAIL] File not found: $LOGFILE${NC}" && exit 1

# Générer des noms de fichiers uniques basés sur le nom du fichier d'entrée
INPUT_BASENAME=$(basename "$LOGFILE")
SAFE_NAME=$(echo "$INPUT_BASENAME" | sed 's/[\/\\]/_/g')
JSON_FILE="analysis_${SAFE_NAME}.json"
DASHBOARD_FILE="dashboard_${SAFE_NAME}.png"

echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   SSH THREAT ANALYZER  -  Docker Mode       ║"
echo "  ║   Created by  >>>  ES-SYAGI HAMZA           ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 1 : Build ──────────────────────────────────────────────
echo -e "${CYAN}[1/3] Building Docker image...${NC}"
docker build -t ssh-threat-analyzer . -q
echo -e "${GREEN}[OK] Image built${NC}"

# ── Step 2 : Analyze ────────────────────────────────────────────
echo -e "${CYAN}[2/3] Running analysis on $LOGFILE ...${NC}"
docker run --rm \
    -v "$(pwd):/data" \
    ssh-threat-analyzer \
    /data/"$LOGFILE" -o /data/output --json-name "$JSON_FILE"

# ── Step 3 : Visualize ──────────────────────────────────────────
echo -e "${CYAN}[3/3] Generating dashboard...${NC}"
docker run --rm \
    -v "$(pwd):/data" \
    --entrypoint python3 \
    ssh-threat-analyzer \
    scripts/visualize.py "/data/output/$JSON_FILE" -o "/data/output/$DASHBOARD_FILE"

echo ""
echo -e "${GREEN}${BOLD}✅ Done!${NC}"
echo -e "  Dashboard  : ${CYAN}output/$DASHBOARD_FILE${NC}"
echo -e "  JSON data  : ${CYAN}output/$JSON_FILE${NC}"
echo -e "  LinkedIn   : ${CYAN}output/linkedin_post.txt${NC}"
echo ""
echo -e "  Open image :"
echo -e "  ${BOLD}explorer.exe output/$DASHBOARD_FILE${NC}"
