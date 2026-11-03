#!/usr/bin/env bash
#
# recon.sh - subdomain -> live-host -> content-discovery -> vuln-template pipeline.
# Reads scope from ../config/targets.env. Authorized testing only.
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${HERE}/../config/targets.env"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[!] ${ENV_FILE} not found."
  echo "    cp config/targets.example.env config/targets.env  and fill it in."
  exit 1
fi
# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

: "${TARGET_DOMAIN:?set TARGET_DOMAIN in targets.env}"
: "${OUT_DIR:=./out}"
: "${WORDLIST:=/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt}"
BASE_URL="${BASE_URL:-https://${TARGET_DOMAIN}}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[!] missing tool: $1"; MISSING=1; }; }
MISSING=0
for t in subfinder httpx ffuf nuclei; do need "$t"; done
[[ "$MISSING" -eq 1 ]] && { echo "[!] install the tools above and re-run."; exit 1; }

STAMP="$(date +%Y%m%d-%H%M%S)"
RUN="${OUT_DIR}/${TARGET_DOMAIN}/${STAMP}"
mkdir -p "$RUN"
echo "[*] target : ${TARGET_DOMAIN}"
echo "[*] app     : ${BASE_URL}"
echo "[*] output  : ${RUN}"
echo

echo "==> [1/4] subfinder - passive subdomain enumeration"
subfinder -silent -d "$TARGET_DOMAIN" | sort -u > "${RUN}/subs.txt"
echo "    $(wc -l < "${RUN}/subs.txt") subdomains"

echo "==> [2/4] httpx - probing for live HTTP(S) hosts"
httpx -silent -l "${RUN}/subs.txt" -sc -title -tech-detect -o "${RUN}/live.txt" || true
# bare host list for the next stages
cut -d' ' -f1 "${RUN}/live.txt" 2>/dev/null | sed -E 's#https?://##' | sort -u > "${RUN}/live_hosts.txt" || true
echo "    $(wc -l < "${RUN}/live.txt" 2>/dev/null || echo 0) live endpoints"

echo "==> [3/4] ffuf - content discovery on ${BASE_URL}"
if [[ -f "$WORDLIST" ]]; then
  ffuf -s -u "${BASE_URL}/FUZZ" -w "$WORDLIST" -mc 200,204,301,302,307,401,403 \
       -o "${RUN}/ffuf.json" -of json || true
else
  echo "    [!] wordlist not found: ${WORDLIST} - skipping ffuf"
fi

echo "==> [4/4] nuclei - vulnerability templates against live hosts"
if [[ -s "${RUN}/live.txt" ]]; then
  nuclei -silent -l "${RUN}/live.txt" -severity low,medium,high,critical \
         -o "${RUN}/nuclei.txt" || true
  echo "    $(wc -l < "${RUN}/nuclei.txt" 2>/dev/null || echo 0) findings"
else
  echo "    [!] no live hosts - skipping nuclei"
fi

echo
echo "[+] done. results in ${RUN}/"
