#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
case_filter="${CASE:-all}"
run_case() {
  local label="$1" expected="$2" pod="$3" token="$4" method="$5" result code
  result="$(kubectl -n shop exec "deploy/$pod" -- /lab call "$token" "$method")"
  code="${result#HTTP }"; code="${code%% *}"
  printf '%s  %s\n' "$code" "$label"
  if [[ "$code" != "$expected" ]]; then printf 'expected %s, got %s: %s\n' "$expected" "$code" "$result" >&2; exit 1; fi
}
if [[ "$case_filter" == all || "$case_filter" == allow ]]; then
  inventory_token="$(kubectl -n shop exec deploy/order -- /lab token prod inventory-read)"
  run_case 'order → inventory (GET, inventory-read)' 200 order "$inventory_token" GET
fi
if [[ "$case_filter" == all || "$case_filter" == deny ]]; then
  inventory_token="${inventory_token:-$(kubectl -n shop exec deploy/order -- /lab token prod inventory-read)}"
  billing_token="$(kubectl -n shop exec deploy/order -- /lab token prod billing-read)"
  run_case 'token audience = billing' 401 order "$billing_token" GET
  run_case 'inventory-read cannot authorize POST' 403 order "$inventory_token" POST
  run_case 'peer = spiffe://prod.demo/ns/shop/sa/other' 403 other "$inventory_token" GET
fi
if [[ "$case_filter" == staging ]]; then
  stage_token="$(kubectl -n shop exec deploy/order -- /lab token staging inventory-read)"
  run_case 'staging issuer at prod inventory' 401 order "$stage_token" GET
fi
