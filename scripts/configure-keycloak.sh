#!/usr/bin/env bash
set -euo pipefail

kc() {
  kubectl -n shop exec deploy/keycloak -- /opt/keycloak/bin/kcadm.sh "$@"
}

kc config credentials --server http://localhost:8080 --realm master --user admin --password lab-only-change-me >/dev/null

for realm in prod staging; do
  if ! kc get authentication/flows -r "$realm" | jq -e '.[] | select(.alias == "spiffe-clients")' >/dev/null; then
    kc create authentication/flows/clients/copy -r "$realm" -s newName=spiffe-clients >/dev/null
  fi

  executions="$(kc get authentication/flows/spiffe-clients/executions -r "$realm")"
  if ! jq -e '.[] | select(.providerId == "spiffe-x509")' <<< "$executions" >/dev/null; then
    kc create authentication/flows/spiffe-clients/executions/execution -r "$realm" -s provider=spiffe-x509 >/dev/null
    executions="$(kc get authentication/flows/spiffe-clients/executions -r "$realm")"
  fi

  while IFS=$'\t' read -r id requirement; do
    if [[ "$requirement" != REQUIRED ]]; then
      kc update authentication/flows/spiffe-clients/executions -r "$realm" -s "id=$id" -s requirement=REQUIRED -n
    fi
  done < <(jq -r '.[] | select(.providerId == "spiffe-x509") | [.id,.requirement] | @tsv' <<< "$executions")

  while IFS=$'\t' read -r id requirement; do
    if [[ "$requirement" != DISABLED ]]; then
      kc update authentication/flows/spiffe-clients/executions -r "$realm" -s "id=$id" -s requirement=DISABLED -n
    fi
  done < <(jq -r '.[] | select(.providerId != "spiffe-x509") | [.id,.requirement] | @tsv' <<< "$executions")

  kc update "realms/$realm" -s clientAuthenticationFlow=spiffe-clients >/dev/null
done

printf 'Keycloak requires the SPIFFE X.509 client authenticator in prod and staging.\n'
