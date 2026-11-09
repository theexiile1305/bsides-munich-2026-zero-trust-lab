SHELL := /bin/bash
.PHONY: up demo test logs policy-test down
up:
	./scripts/up.sh
demo:
	CASE=$(or $(CASE),all) ./scripts/demo.sh
test:
	CASE=all ./scripts/demo.sh
	CASE=staging ./scripts/demo.sh
logs:
	kubectl -n shop logs -f deploy/inventory -c inventory
policy-test:
	docker run --rm -v $(CURDIR)/policy:/policy openpolicyagent/opa:1.21.0 test /policy -v
down:
	kind delete cluster --name bsides-zt
