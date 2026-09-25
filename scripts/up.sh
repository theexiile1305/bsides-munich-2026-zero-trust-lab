#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .local
if ! kind get clusters | grep -qx 'bsides-zt'; then
  kind create cluster --name bsides-zt --image kindest/node:v1.35.5
fi
kubectl config use-context kind-bsides-zt >/dev/null
helm upgrade --install spire-crds spire-crds --repo https://spiffe.github.io/helm-charts-hardened/ --version 0.6.1 --namespace spire --create-namespace --wait --timeout 8m
helm upgrade --install spire spire --repo https://spiffe.github.io/helm-charts-hardened/ --version 0.30.0 --namespace spire --values helm/spire-values.yaml --wait --timeout 8m

docker build -t bsides-keycloak:26.7.4 extension
docker build -t bsides-lab:1.0.0 app
kind load docker-image --name bsides-zt bsides-keycloak:26.7.4 bsides-lab:1.0.0

kubectl create namespace shop --dry-run=client -o yaml | kubectl apply -f -
if [[ ! -s .local/tls.crt || ! -s .local/tls.key ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 7 \
    -keyout .local/tls.key -out .local/tls.crt \
    -subj '/CN=keycloak.shop.svc.cluster.local' \
    -addext 'subjectAltName=DNS:keycloak.shop.svc.cluster.local' >/dev/null 2>&1
fi
kubectl -n shop create secret tls keycloak-tls --cert=.local/tls.crt --key=.local/tls.key --dry-run=client -o yaml | kubectl apply -f -
kubectl -n shop create configmap keycloak-realms --from-file=realm/prod-realm.json --from-file=realm/staging-realm.json --dry-run=client -o yaml | kubectl apply -f -
kubectl -n shop create configmap inventory-policy --from-file=inventory.rego=policy/inventory.rego --dry-run=client -o yaml | kubectl apply -f -
kubectl -n spire exec spire-server-0 -c spire-server -- spire-server bundle show -format pem > .local/bundle.pem
kubectl -n shop create configmap spire-trust-bundle --from-file=bundle.pem=.local/bundle.pem --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f k8s/shop.yaml
kubectl -n shop rollout status deployment/keycloak --timeout=5m
kubectl -n shop rollout status deployment/inventory --timeout=5m
kubectl -n shop rollout status deployment/order --timeout=5m
kubectl -n shop rollout status deployment/other --timeout=5m
./scripts/configure-keycloak.sh
printf 'Ready. Run make demo, then make test.\n'
