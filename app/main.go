package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	issuerBase   = "https://keycloak.shop.svc.cluster.local:8443/realms/"
	inventoryURL = "https://inventory.shop.svc.cluster.local:8443/inventory/items/42"
	inventoryID  = "spiffe://prod.demo/ns/shop/sa/inventory"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: lab inventory|token [realm scope]|call [token method]")
	}
	ctx := context.Background()
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer source.Close()
	switch os.Args[1] {
	case "inventory":
		log.Fatal(serveInventory(ctx))
	case "token":
		if len(os.Args) != 4 {
			log.Fatal("usage: lab token realm scope")
		}
		token, err := requestToken(ctx, source, os.Args[2], os.Args[3])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(token)
	case "call":
		if len(os.Args) != 4 {
			log.Fatal("usage: lab call token method")
		}
		code, body, err := callInventory(ctx, os.Args[2], os.Args[3])
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("HTTP %d %s\n", code, body)
	default:
		log.Fatal("unknown command")
	}
}

func clientCertificate(source *workloadapi.X509Source) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		svid, err := source.GetX509SVID()
		if err != nil {
			return nil, err
		}
		cert := &tls.Certificate{PrivateKey: svid.PrivateKey, Leaf: svid.Certificates[0]}
		for _, c := range svid.Certificates {
			cert.Certificate = append(cert.Certificate, c.Raw)
		}
		return cert, nil
	}
}

func keycloakClient(source *workloadapi.X509Source) (*http.Client, error) {
	pem, err := os.ReadFile("/etc/keycloak-ca/tls.crt")
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("invalid Keycloak CA")
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, GetClientCertificate: clientCertificate(source)}}}, nil
}

func requestToken(ctx context.Context, source *workloadapi.X509Source, realm, scope string) (string, error) {
	client, err := keycloakClient(source)
	if err != nil {
		return "", err
	}
	body := strings.NewReader("grant_type=client_credentials&client_id=order&scope=" + scope)
	req, err := http.NewRequestWithContext(ctx, "POST", issuerBase+realm+"/protocol/openid-connect/token", body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Keycloak %d: %s", resp.StatusCode, payload)
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
	}
	if err = json.Unmarshal(payload, &decoded); err != nil {
		return "", err
	}
	if decoded.AccessToken == "" {
		return "", errors.New("missing access_token")
	}
	return decoded.AccessToken, nil
}

func callInventory(ctx context.Context, token, method string) (int, string, error) {
	id := spiffeid.RequireFromString(inventoryID)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return spiffetls.Dial(ctx, network, addr, tlsconfig.AuthorizeID(id))
	}}}
	req, err := http.NewRequestWithContext(ctx, method, inventoryURL, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, strings.TrimSpace(string(body)), nil
}

// Cached JWKS uses local signature validation on every call. Unknown kid triggers one
// bounded refresh. A downstream 401 never triggers a key fetch.
type keyCache struct {
	mu                  sync.Mutex
	keys                map[string]*rsa.PublicKey
	expires             time.Time
	unknownRefreshAfter time.Time
	client              *http.Client
}

func (c *keyCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if key := c.keys[kid]; key != nil && time.Now().Before(c.expires) {
		return key, nil
	}
	if c.keys[kid] == nil && time.Now().Before(c.unknownRefreshAfter) {
		return nil, errors.New("unknown kid (refresh cooldown)")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", issuerBase+"prod/protocol/openid-connect/certs", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("JWKS status %d", resp.StatusCode)
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return nil, err
	}
	next := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || j.Kid == "" || j.N == "" || j.E == "" {
			continue
		}
		nb, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			continue
		}
		eb, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			continue
		}
		exp := new(big.Int).SetBytes(eb)
		if !exp.IsInt64() || exp.Int64() <= 1 {
			continue
		}
		next[j.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(exp.Int64())}
	}
	if len(next) == 0 {
		return nil, errors.New("empty RSA JWKS")
	}
	c.keys = next
	c.expires = time.Now().Add(2 * time.Minute)
	c.unknownRefreshAfter = time.Now().Add(5 * time.Second)
	if key := next[kid]; key != nil {
		return key, nil
	}
	return nil, errors.New("unknown kid")
}

type claims struct {
	Iss   string `json:"iss"`
	Aud   any    `json:"aud"`
	Azp   string `json:"azp"`
	Scope string `json:"scope"`
	Exp   int64  `json:"exp"`
	Nbf   int64  `json:"nbf"`
}

func validateToken(ctx context.Context, c *keyCache, raw string) (claims, error) {
	var out claims
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return out, errors.New("not a JWT")
	}
	headBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return out, err
	}
	var head struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err = json.Unmarshal(headBytes, &head); err != nil {
		return out, err
	}
	if head.Alg != "RS256" || head.Kid == "" {
		return out, errors.New("unexpected alg or kid")
	}
	key, err := c.key(ctx, head.Kid)
	if err != nil {
		return out, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return out, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err = rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return out, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal(payload, &out); err != nil {
		return out, err
	}
	now := time.Now().Unix()
	if out.Iss != issuerBase+"prod" || out.Exp <= now || (out.Nbf != 0 && out.Nbf > now) {
		return out, errors.New("issuer or time invalid")
	}
	if !hasAudience(out.Aud, "inventory") {
		return out, errors.New("audience invalid")
	}
	return out, nil
}
func hasAudience(raw any, want string) bool {
	switch v := raw.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if a == want {
				return true
			}
		}
	}
	return false
}

func serveInventory(ctx context.Context) error {
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return err
	}
	defer source.Close()
	kc, err := keycloakClient(source)
	if err != nil {
		return err
	}
	cache := &keyCache{keys: map[string]*rsa.PublicKey{}, client: kc}
	mux := http.NewServeMux()
	mux.HandleFunc("/inventory/items/42", func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if raw == "" || raw == r.Header.Get("Authorization") {
			http.Error(w, "invalid_token", 401)
			return
		}
		token, err := validateToken(r.Context(), cache, raw)
		if err != nil {
			http.Error(w, "invalid_token", 401)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 {
			http.Error(w, "invalid_peer", 403)
			return
		}
		peer := r.TLS.PeerCertificates[0].URIs[0].String()
		input := map[string]any{"peer": peer, "authorized_party": token.Azp, "audience": "inventory", "method": r.Method, "path": r.URL.Path, "scopes": strings.Fields(token.Scope)}
		data, _ := json.Marshal(map[string]any{"input": input})
		req, err := http.NewRequestWithContext(r.Context(), "POST", "http://127.0.0.1:8181/v1/data/inventory/authz/allow", bytes.NewReader(data))
		if err != nil {
			http.Error(w, "policy_error", 503)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: time.Second}).Do(req)
		if err != nil {
			http.Error(w, "policy_error", 503)
			return
		}
		defer resp.Body.Close()
		var decision struct {
			Result bool `json:"result"`
		}
		if resp.StatusCode != 200 || json.NewDecoder(resp.Body).Decode(&decision) != nil {
			http.Error(w, "policy_error", 503)
			return
		}
		if !decision.Result {
			http.Error(w, "forbidden", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"sku":"42","available":true}`)
	})
	listener, err := spiffetls.Listen(ctx, "tcp", ":8443", tlsconfig.AuthorizeAny())
	if err != nil {
		return err
	}
	log.Println("inventory listening on 8443 with SPIFFE mTLS")
	return (&http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)
}
