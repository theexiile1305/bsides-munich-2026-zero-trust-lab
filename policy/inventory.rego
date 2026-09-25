package inventory.authz

default allow := false

allow if {
  input.peer == "spiffe://prod.demo/ns/shop/sa/order"
  input.authorized_party == "order"
  input.audience == "inventory"
  input.method == "GET"
  input.path == "/inventory/items/42"
  "inventory-read" in input.scopes
}
