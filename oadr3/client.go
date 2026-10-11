package oadr3

// APIClient is an OpenADR 3 REST client: it obtains tokens with the OAuth2
// client-credentials grant (discovering the token endpoint through GET
// /auth/server), sends requests with the bearer token, fetches a new token
// once when the VTN answers 401, and checks its requests and the VTN's
// answers against the OpenAPI definition when a validator is set. VENs,
// business-logic clients and the openadr-sim simulators use it.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ClientConfig configures an APIClient.
type ClientConfig struct {
	// BaseURL is the VTN's URL up to its base path.
	BaseURL string
	// ClientID and Secret are the client credentials; without them the
	// client sends no token (a non-authenticating VTN).
	ClientID, Secret string
	// TokenURL overrides discovery through GET /auth/server.
	TokenURL string
	// Scope asks for particular scopes (space separated).
	Scope   string
	RootCAs *x509.CertPool
	// InsecureSkipVerify accepts an unverified VTN certificate (a VEN
	// may offer this setting; the default verifies).
	InsecureSkipVerify bool
	Timeout            time.Duration
	// Validator checks requests and answers (nil: no checks).
	Validator Validator
}

// Validator checks the client's messages against the OpenAPI definition
// (one built on the user's own copy of the OpenADR 3 YAML, say). Each
// method returns an error only when the exchange must stop.
type Validator interface {
	// Schema checks a body against a named component schema.
	Schema(name string, body []byte) error
	// Request checks a request; path is relative to the base path.
	Request(method, path string, query url.Values, contentType string, body []byte) error
	// Response checks an answer.
	Response(method, path string, status int, contentType string, body []byte) error
}

// noValidator accepts everything.
type noValidator struct{}

func (noValidator) Schema(string, []byte) error { return nil }
func (noValidator) Request(string, string, url.Values, string, []byte) error {
	return nil
}
func (noValidator) Response(string, string, int, string, []byte) error { return nil }

func (c *APIClient) val() Validator {
	if c.cfg.Validator == nil {
		return noValidator{}
	}
	return c.cfg.Validator
}

// APIClient talks to one VTN.
type APIClient struct {
	cfg  ClientConfig
	http *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// HTTPError is a VTN answer outside 2xx.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("VTN answered %d: %s", e.Status, e.Body) }

// NewClient makes a client.
func NewClient(cfg ClientConfig) *APIClient {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs,
		InsecureSkipVerify: cfg.InsecureSkipVerify}} //nolint:gosec // an explicit, documented setting
	return &APIClient{cfg: cfg, http: &http.Client{Timeout: cfg.Timeout, Transport: tr}}
}

// ClientID is the client's ID ("" when anonymous).
func (c *APIClient) ClientID() string { return c.cfg.ClientID }

// Token gives a valid access token, fetching one when needed.
func (c *APIClient) Token(ctx context.Context) (string, error) {
	if c.cfg.ClientID == "" {
		return "", nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.expiry) {
		return c.token, nil
	}
	tokenURL := c.cfg.TokenURL
	if tokenURL == "" {
		var info struct {
			TokenURL string `json:"tokenURL"`
		}
		if _, err := c.raw(ctx, http.MethodGet, "/auth/server", nil, "", nil, "", &info); err != nil {
			return "", fmt.Errorf("discovering the token endpoint: %w", err)
		}
		if info.TokenURL == "" {
			return "", errors.New("GET /auth/server gave no tokenURL")
		}
		tokenURL = info.TokenURL
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.cfg.ClientID}, "client_secret": {c.cfg.Secret}}
	if c.cfg.Scope != "" {
		form.Set("scope", c.cfg.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", &HTTPError{Status: resp.StatusCode, Body: string(b)}
	}
	if err := c.val().Schema("clientCredentialResponse", b); err != nil {
		return "", err
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &tr); err != nil || tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "Bearer") {
		return "", fmt.Errorf("the token endpoint gave no bearer token: %s", b)
	}
	life := time.Duration(tr.ExpiresIn) * time.Second
	if life <= 0 {
		life = 5 * time.Minute
	}
	c.token, c.expiry = tr.AccessToken, time.Now().Add(life*9/10)
	return c.token, nil
}

// Forget drops the cached token.
func (c *APIClient) Forget() {
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
}

// Do sends a request (body nil or a JSON value) and decodes the answer
// into out (when not nil). It returns the HTTP status.
func (c *APIClient) Do(ctx context.Context, method, path string, q url.Values, body, out any) (int, error) {
	var b []byte
	ct := ""
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return 0, err
		}
		ct = "application/json"
	}
	if err := c.val().Request(method, path, q, ct, b); err != nil {
		return 0, fmt.Errorf("not sent: %w", err)
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.Token(ctx)
		if err != nil {
			return 0, err
		}
		status, err := c.raw(ctx, method, path, q, ct, b, tok, out)
		var he *HTTPError
		if attempt == 0 && errors.As(err, &he) && he.Status == http.StatusUnauthorized && c.cfg.ClientID != "" {
			c.Forget()
			continue
		}
		return status, err
	}
}

func (c *APIClient) raw(ctx context.Context, method, path string, q url.Values, ct string, body []byte, tok string, out any) (int, error) {
	u := c.cfg.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Accept", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if verr := c.val().Response(method, path, resp.StatusCode, resp.Header.Get("Content-Type"), rb); verr != nil {
		return resp.StatusCode, fmt.Errorf("the VTN's answer to %s %s does not match the OpenAPI definition: %w", method, path, verr)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, &HTTPError{Status: resp.StatusCode, Body: strings.TrimSpace(string(rb))}
	}
	if out != nil && len(rb) > 0 {
		if err := json.Unmarshal(rb, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decoding the answer to %s %s: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// All pages through a search (skip/limit) and gives every object.
func (c *APIClient) All(ctx context.Context, path string, q url.Values) ([]Object, error) {
	var all []Object
	for skip := 0; ; {
		qq := url.Values{}
		for k, v := range q {
			qq[k] = v
		}
		qq.Set("skip", fmt.Sprint(skip))
		qq.Set("limit", fmt.Sprint(MaxLimit))
		var page []Object
		if _, err := c.Do(ctx, http.MethodGet, path, qq, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page...)
		if len(page) < MaxLimit {
			return all, nil
		}
		skip += len(page)
	}
}
