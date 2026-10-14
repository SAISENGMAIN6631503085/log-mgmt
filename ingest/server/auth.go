package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Keys finds the tenant an ingest API key belongs to ("" if the key is unknown or revoked).
type Keys interface {
	TenantForKey(ctx context.Context, key string) (string, error)
}

// PostgresKeys reads the api_keys table the Python backend manages (create, list, revoke).
// Only the SHA-256 of a key is stored, so a stolen database doesn't give working keys.
type PostgresKeys struct{ Pool *pgxpool.Pool }

func (k PostgresKeys) TenantForKey(ctx context.Context, key string) (string, error) {
	sum := sha256.Sum256([]byte(key))
	var tenant string
	err := k.Pool.QueryRow(ctx, "SELECT tenant FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL",
		hex.EncodeToString(sum[:])).Scan(&tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return tenant, err
}

// tenantFromAPIKey: the tenant is decided by the key, never by the request body.
func (s *Server) tenantFromAPIKey(r *http.Request) (string, *httpError) {
	key := r.Header.Get("X-API-Key")
	if key == "" {
		return "", &httpError{http.StatusUnauthorized, "missing X-API-Key header"}
	}
	tenant, err := s.Keys.TenantForKey(r.Context(), key)
	if err != nil {
		return "", &httpError{http.StatusServiceUnavailable, "can't check the API key right now; retry later"}
	}
	if tenant == "" {
		// Same message for unknown and revoked keys: don't tell an attacker which one it was.
		return "", &httpError{http.StatusUnauthorized, "invalid API key"}
	}
	return tenant, nil
}

// Claims are what the backend puts in its login tokens (see backend/app/auth.py).
type Claims struct {
	Role   string `json:"role"`
	Tenant string `json:"tenant"`
	jwt.RegisteredClaims
}

// adminTenant checks the website's login token for the "Add logs" upload: admins only, and the
// tenant is the one being viewed (?tenant=), the same rule the backend applies everywhere.
func (s *Server) adminTenant(r *http.Request) (string, *httpError) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return "", &httpError{http.StatusUnauthorized, "missing bearer token"}
	}
	var c Claims
	// The algorithm is pinned: never let the token's own header choose it ("alg": "none").
	_, err := jwt.ParseWithClaims(token, &c, func(*jwt.Token) (any, error) { return []byte(s.Config.JWTSecret), nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil || c.Subject == "" || c.Tenant == "" || (c.Role != "admin" && c.Role != "viewer") {
		return "", &httpError{http.StatusUnauthorized, "invalid or expired token"}
	}
	if c.Role != "admin" {
		return "", &httpError{http.StatusForbidden, "admin only"}
	}
	if t := r.URL.Query().Get("tenant"); t != "" {
		return t, nil // admins may switch tenants
	}
	return c.Tenant, nil
}
