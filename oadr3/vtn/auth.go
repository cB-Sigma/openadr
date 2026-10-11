// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

// OAuth2 client credentials and bearer tokens. The token format is the
// VTN's choice: an HS256 JSON Web Token (RFC 7519) whose claims are the
// client ID (sub), its role, the granted scopes and issue and expiry
// times. The token endpoint is the client-credentials grant of RFC 6749
// section 4.4, with the credentials in the form body (client_secret_post)
// or HTTP Basic authentication (client_secret_basic).

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cB-Sigma/openadr/oadr3"
)

// Scopes of the OpenADR 3.1 oAuth2ClientCredentials scheme. read_bl is
// named by some 3.1.0 operations without being among the scheme's
// declared scopes; it is granted to business logic only.
const (
	ScopeReadAll            = "read_all"
	ScopeReadTargets        = "read_targets"
	ScopeReadVenObjects     = "read_ven_objects"
	ScopeReadBL             = "read_bl"
	ScopeWritePrograms      = "write_programs"
	ScopeWriteEvents        = "write_events"
	ScopeWriteReports       = "write_reports"
	ScopeWriteSubscriptions = "write_subscriptions"
	ScopeWriteVens          = "write_vens"
)

// RoleScopes are the scopes each role may hold in OpenADR 3.1: business
// logic writes programs and events and reads everything; a VEN reads what
// it is targeted by or owns and writes reports, subscriptions, vens and
// resources.
var RoleScopes = map[string][]string{
	RoleBL: {ScopeReadAll, ScopeReadTargets, ScopeReadVenObjects, ScopeReadBL, ScopeWritePrograms, ScopeWriteEvents,
		ScopeWriteSubscriptions, ScopeWriteVens},
	RoleVEN: {ScopeReadTargets, ScopeReadVenObjects, ScopeWriteReports, ScopeWriteSubscriptions, ScopeWriteVens},
}

// RoleScopes30 are the scopes of OpenADR 3.0, which has a single read
// scope.
var RoleScopes30 = map[string][]string{
	RoleBL:  {ScopeReadAll, ScopeWritePrograms, ScopeWriteEvents, ScopeWriteSubscriptions, ScopeWriteVens},
	RoleVEN: {ScopeReadAll, ScopeWriteReports, ScopeWriteSubscriptions, ScopeWriteVens},
}

func (v *VTN) roleScopes(role string) []string {
	if v.cfg.Version == Version30 {
		return RoleScopes30[role]
	}
	return RoleScopes[role]
}

// Principal is the authenticated client of a request.
type Principal struct {
	ClientID string
	// Role is RoleBL or RoleVEN.
	Role   string
	Scopes []string
}

// BL says whether p acts as business logic.
func (p *Principal) BL() bool { return p != nil && p.Role == RoleBL }

// Has says whether p holds scope.
func (p *Principal) Has(scope string) bool { return p != nil && contains(p.Scopes, scope) }

// Authenticator checks a bearer token the VTN did not issue (from an
// external authorisation server). It returns the principal, or an error
// for a token it refuses. The VTN keeps only the principal's scopes its
// role allows.
type Authenticator interface {
	Authenticate(r *http.Request, token string) (*Principal, error)
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(r *http.Request, token string) (*Principal, error)

// Authenticate calls f.
func (f AuthenticatorFunc) Authenticate(r *http.Request, token string) (*Principal, error) {
	return f(r, token)
}

type claims struct {
	Sub   string `json:"sub"`
	Role  string `json:"role"`
	Scope string `json:"scope"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

var b64 = base64.RawURLEncoding

const tokenHead = `{"alg":"HS256","typ":"JWT"}`

// IssueToken makes a token for a configured client with the given scopes
// (nil: every scope its role allows), as the token endpoint would.
func (v *VTN) IssueToken(clientID string, scopes []string) (token string, expiresIn time.Duration, err error) {
	c := v.clients[clientID]
	if c == nil {
		return "", 0, errors.New("vtn: unknown client " + clientID)
	}
	if scopes == nil {
		scopes = v.clientScopes(c)
	}
	tok, life := v.issue(c, scopes)
	return tok, life, nil
}

func (v *VTN) clientScopes(c *Client) []string {
	if len(c.Scopes) > 0 {
		return c.Scopes
	}
	return v.roleScopes(c.Role)
}

func (v *VTN) issue(c *Client, scopes []string) (string, time.Duration) {
	now := v.now()
	life := v.cfg.TokenLifetime
	head := b64.EncodeToString([]byte(tokenHead))
	body, _ := json.Marshal(claims{Sub: c.ClientID, Role: c.Role, Scope: strings.Join(scopes, " "), Iat: now.Unix(), Exp: now.Add(life).Unix()})
	msg := head + "." + b64.EncodeToString(body)
	m := hmac.New(sha256.New, v.key)
	m.Write([]byte(msg))
	return msg + "." + b64.EncodeToString(m.Sum(nil)), life
}

var errToken = errors.New("the bearer token is missing, malformed, badly signed or expired")

// ownToken checks a token the VTN issued. ok is false when the token is
// not an HS256 token at all (it may be an external one).
func (v *VTN) ownToken(tok string) (p *Principal, ok bool, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, false, errToken
	}
	var head struct{ Alg string }
	hb, err := b64.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &head) != nil {
		return nil, false, errToken
	}
	if head.Alg != "HS256" {
		return nil, false, nil
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, true, errToken
	}
	m := hmac.New(sha256.New, v.key)
	m.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, m.Sum(nil)) {
		return nil, true, errToken
	}
	cb, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, true, errToken
	}
	var c claims
	if json.Unmarshal(cb, &c) != nil || c.Sub == "" || v.now().Unix() >= c.Exp {
		return nil, true, errToken
	}
	return &Principal{ClientID: c.Sub, Role: c.Role, Scopes: strings.Fields(c.Scope)}, true, nil
}

// verify checks a bearer token and gives its principal, with the scopes
// limited to what its role allows.
func (v *VTN) verify(r *http.Request, tok string) (*Principal, error) {
	p, own, err := v.ownToken(tok)
	if !own {
		if v.cfg.Authenticator == nil {
			return nil, errToken
		}
		if p, err = v.cfg.Authenticator.Authenticate(r, tok); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if p == nil || p.ClientID == "" {
		return nil, errToken
	}
	allowed := v.roleScopes(p.Role)
	if allowed == nil {
		return nil, errToken
	}
	var scopes []string
	for _, s := range p.Scopes {
		if contains(allowed, s) {
			scopes = append(scopes, s)
		}
	}
	return &Principal{ClientID: p.ClientID, Role: p.Role, Scopes: scopes}, nil
}

// authenticate reads the Authorization header: no header is anonymous
// (nil), a bad token an error.
func (v *VTN) authenticate(r *http.Request) (*Principal, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, nil
	}
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(tok) == "" {
		return nil, errToken
	}
	return v.verify(r, strings.TrimSpace(tok))
}

// scope30 maps a 3.1 read scope to 3.0's single read scope.
func (v *VTN) scopeFor(scope string) string {
	if v.cfg.Version == Version30 {
		switch scope {
		case ScopeReadTargets, ScopeReadVenObjects, ScopeReadBL:
			return ScopeReadAll
		}
	}
	return scope
}

// access authenticates r and checks the operation's scope; anonymousOK
// allows anonymous reads when the VTN is configured for them.
func (v *VTN) access(r *http.Request, scope string, anonymousOK bool) (*Principal, error) {
	p, err := v.authenticate(r)
	if err != nil {
		return nil, unauthorized(err.Error())
	}
	if p == nil {
		if anonymousOK && v.cfg.AnonymousRead {
			return nil, nil
		}
		return nil, unauthorized("a valid bearer token is required")
	}
	if !p.Has(v.scopeFor(scope)) {
		return nil, oadr3.Forbidden("the operation needs scope %s", v.scopeFor(scope))
	}
	return p, nil
}

// authServer answers GET /auth/server with the token endpoint's URL.
func (v *VTN) authServer(w http.ResponseWriter, r *http.Request) {
	u := v.cfg.TokenURL
	if u == "" {
		u = v.baseURL(r) + "/auth/token"
	}
	v.reply(w, r, http.StatusOK, map[string]any{"tokenURL": u})
}

func authError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": code, "error_description": desc})
}

// authToken is the token endpoint.
func (v *VTN) authToken(w http.ResponseWriter, r *http.Request) {
	if v.cfg.TokenURL != "" {
		v.problem(w, r, &oadr3.Problem{Status: http.StatusNotImplemented, Title: "Not Implemented",
			Detail: "this VTN's tokens come from the authorisation server GET /auth/server names"})
		return
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/x-www-form-urlencoded" {
		authError(w, http.StatusBadRequest, "invalid_request", "the body must be application/x-www-form-urlencoded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		authError(w, http.StatusBadRequest, "invalid_request", "the form cannot be read")
		return
	}
	form := r.PostForm
	for k, x := range form {
		if len(x) > 1 {
			authError(w, http.StatusBadRequest, "invalid_request", "parameter "+k+" is repeated")
			return
		}
	}
	id, secret := form.Get("client_id"), form.Get("client_secret")
	if u, p, ok := r.BasicAuth(); ok {
		if secret != "" || (id != "" && id != u) {
			authError(w, http.StatusBadRequest, "invalid_request", "use one client authentication method")
			return
		}
		id, _ = url.QueryUnescape(u)
		secret, _ = url.QueryUnescape(p)
	}
	if v.cfg.Validator != nil {
		_ = v.cfg.Validator.Request(r.Method, "/auth/token", nil, "application/x-www-form-urlencoded", formBody(form, id, secret))
	}
	switch gt := form.Get("grant_type"); {
	case gt == "":
		authError(w, http.StatusBadRequest, "invalid_request", "grant_type is missing")
		return
	case gt != "client_credentials":
		authError(w, http.StatusBadRequest, "unsupported_grant_type", "only client_credentials is supported")
		return
	}
	if id == "" || secret == "" {
		authError(w, http.StatusBadRequest, "invalid_request", "client_id and client_secret are required")
		return
	}
	c := v.clients[id]
	if c == nil || subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="openadr3"`)
		authError(w, http.StatusUnauthorized, "invalid_client", "unknown client or wrong secret")
		return
	}
	scopes := v.clientScopes(c)
	if req := strings.Fields(form.Get("scope")); len(req) > 0 {
		for _, s := range req {
			if !contains(scopes, s) {
				authError(w, http.StatusBadRequest, "invalid_scope", "scope "+s+" is not available to this client")
				return
			}
		}
		scopes = req
	}
	tok, life := v.issue(c, scopes)
	w.Header().Set("Cache-Control", "no-store")
	v.reply(w, r, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer",
		"expires_in": int64(life / time.Second), "scope": strings.Join(scopes, " ")})
}

// formBody gives the token request with the client credentials in the
// form (as the definition's clientCredentialRequest has them), for
// validation.
func formBody(form url.Values, id, secret string) []byte {
	m := url.Values{}
	for k := range form {
		m.Set(k, form.Get(k))
	}
	if id != "" {
		m.Set("client_id", id)
	}
	if secret != "" {
		m.Set("client_secret", secret)
	}
	return []byte(m.Encode())
}
