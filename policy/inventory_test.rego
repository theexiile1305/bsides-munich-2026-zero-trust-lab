package inventory.authz

test_order_read if {
  allow with input as {"peer":"spiffe://prod.demo/ns/shop/sa/order","authorized_party":"order","audience":"inventory","method":"GET","path":"/inventory/items/42","scopes":["inventory-read"]}
}

test_wrong_audience if {
  not allow with input as {"peer":"spiffe://prod.demo/ns/shop/sa/order","authorized_party":"order","audience":"billing","method":"GET","path":"/inventory/items/42","scopes":["inventory-read"]}
}

test_wrong_method if {
  not allow with input as {"peer":"spiffe://prod.demo/ns/shop/sa/order","authorized_party":"order","audience":"inventory","method":"POST","path":"/inventory/items/42","scopes":["inventory-read"]}
}

test_wrong_peer if {
  not allow with input as {"peer":"spiffe://prod.demo/ns/shop/sa/other","authorized_party":"order","audience":"inventory","method":"GET","path":"/inventory/items/42","scopes":["inventory-read"]}
}
