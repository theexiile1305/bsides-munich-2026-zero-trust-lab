#!/usr/bin/env bash
# Narrated demo: each step shows what is attempted, the evidence (token claims,
# caller identity), the client's result and the reason inventory logged.
# CASE=all|allow|deny|staging  PAUSE=1 waits for Enter between steps  NO_COLOR=1 disables colour.
set -euo pipefail
cd "$(dirname "$0")/.."
case_filter="${CASE:-all}"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  bold=$'\e[1m'; dim=$'\e[2m'; red=$'\e[31m'; green=$'\e[32m'; cyan=$'\e[36m'; off=$'\e[0m'
else
  bold=''; dim=''; red=''; green=''; cyan=''; off=''
fi

case "$case_filter" in
  all) total=4 ;;
  allow) total=1 ;;
  deny) total=3 ;;
  staging) total=1 ;;
  *) echo "unknown CASE=$case_filter (all|allow|deny|staging)" >&2; exit 2 ;;
esac
step_no=0

order_exec() { kubectl -n shop exec deploy/order -- "$@"; }

# Print the claims inventory will judge, decoded from the JWT payload.
show_claims() {
  local payload="${1#*.}"; payload="${payload%%.*}"
  payload="$(printf '%s' "$payload" | tr '_-' '/+')"
  while (( ${#payload} % 4 )); do payload+='='; done
  printf '%s' "$payload" | base64 -d | jq -r --arg d "$dim" --arg o "$off" \
    '"    \($d)token claims:\($o) iss=\(.iss | split("/") | last)  aud=\(.aud | tostring)  azp=\(.azp)  scope=\(.scope)  lifetime=\(.exp - .iat)s"'
}

# step <title> <what we try> <expected status> <caller pod> <token> <method>
step() {
  local title="$1" what="$2" expected="$3" pod="$4" token="$5" method="$6" result code
  step_no=$((step_no + 1))
  if [[ -n "${PAUSE:-}" && $step_no -gt 1 ]]; then read -r -p "${dim}[enter for next step]${off} " _ </dev/tty; fi
  printf '\n%s[%d/%d] %s%s\n' "$bold" "$step_no" "$total" "$title" "$off"
  printf '    %s\n' "$what"
  printf '    %scaller:%s spiffe://prod.demo/ns/shop/sa/%s   %srequest:%s %s /inventory/items/42\n' "$dim" "$off" "$pod" "$dim" "$off" "$method"
  show_claims "$token"
  result="$(kubectl -n shop exec "deploy/$pod" -- /lab call "$token" "$method")"
  code="${result#HTTP }"; code="${code%% *}"
  if [[ "$code" == 200 ]]; then
    printf '    %s✓ %s ALLOWED%s\n' "$green" "$code" "$off"
  else
    printf '    %s✗ %s DENIED%s\n' "$red" "$code" "$off"
  fi
  # The server's view: why inventory decided this way.
  kubectl -n shop logs deploy/inventory -c inventory --tail=1 \
    | sed -E 's/^[0-9\/]+ [0-9:]+ //; s/^/    '"${cyan}"'inventory log:'"${off}"' /' || true
  if [[ "$code" != "$expected" ]]; then printf 'expected %s, got %s: %s\n' "$expected" "$code" "$result" >&2; exit 1; fi
}

printf '%sZero Trust lab%s: order → inventory, %s checks\n' "$bold" "$off" "$total"
printf '%sEvery call must pass: SPIFFE mTLS peer, JWT (issuer, audience, expiry), OPA (peer, client, scope, method, path).%s\n' "$dim" "$off"

if [[ "$case_filter" == all || "$case_filter" == allow ]]; then
  inventory_token="$(order_exec /lab token prod inventory-read)"
  step 'Allow: the legitimate call' \
    'order proves its SPIFFE identity to Keycloak, gets an inventory-read token and reads item 42.' \
    200 order "$inventory_token" GET
fi
if [[ "$case_filter" == all || "$case_filter" == deny ]]; then
  inventory_token="${inventory_token:-$(order_exec /lab token prod inventory-read)}"
  billing_token="$(order_exec /lab token prod billing-read)"
  step 'Deny: token meant for another service' \
    'order presents a valid token whose audience is billing, not inventory.' \
    401 order "$billing_token" GET
  step 'Deny: right token, wrong action' \
    'order tries to POST (write) with a read-only scope.' \
    403 order "$inventory_token" POST
  step 'Deny: stolen token, wrong workload' \
    'the "other" pod replays order'"'"'s valid token. The token is fine; the TLS peer is not order.' \
    403 other "$inventory_token" GET
fi
if [[ "$case_filter" == staging ]]; then
  stage_token="$(order_exec /lab token staging inventory-read)"
  step 'Deny: token from the staging issuer' \
    'order presents a token signed by the staging realm to production inventory.' \
    401 order "$stage_token" GET
fi
printf '\n%sAll %d checks behaved as expected.%s\n' "$bold" "$total" "$off"
