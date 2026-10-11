// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

// The OpenADR 3 OpenAPI definition as an oadr3.Validator, for checking
// both ends of the exchanges in these tests. The YAML is fetched at test
// time from a public copy of the OpenADR Alliance release, pinned by
// commit and SHA-256, cached in the user cache directory and never
// shipped with this module (see README, Licence).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// specCommit is the commit of github.com/grid-coordination/openadr3-specification
// the definitions are fetched from (a public copy of the Alliance's
// release; see its README for the upstream commits).
const specCommit = "17b91725e0f07203574ddc946e28def31cb11e44"

var specs = map[string]struct{ path, sha string }{
	"3.1.0": {"3.1.0/openadr3.yaml", "135bc74af2f733338b55afa95df3cb3a1185867e8e41a7d16cdb2dbfaeb3b475"},
	"3.0.1": {"3.0.1/openadr3.yaml", "3418d267d5a916265f5a1c7e08641da8c3507b39abf682d7902658b57fc2e7e7"},
}

// fetchSpec gives the YAML of an OpenADR 3 version, from the cache or
// the network; it skips the test when neither has it.
func fetchSpec(t *testing.T, version string) []byte {
	t.Helper()
	s, ok := specs[version]
	if !ok {
		t.Fatalf("no definition for %s", version)
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	cache := filepath.Join(dir, "sigma-openadr-interop", s.sha+".yaml")
	if b, err := os.ReadFile(cache); err == nil && sum(b) == s.sha {
		return b
	}
	u := "https://raw.githubusercontent.com/grid-coordination/openadr3-specification/" + specCommit + "/" + s.path
	resp, err := http.Get(u)
	if err != nil {
		t.Skipf("cannot fetch the OpenADR %s definition: %v", version, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || sum(b) != s.sha {
		t.Fatalf("the OpenADR %s definition at %s is not the pinned one (status %d, sha256 %s)", version, u, resp.StatusCode, sum(b))
	}
	_ = os.MkdirAll(filepath.Dir(cache), 0o755)
	_ = os.WriteFile(cache, b, 0o644)
	return b
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// specValidator checks messages against a definition and records what
// fails (it never stops an exchange: the test decides).
type specValidator struct {
	doc    *openapi3.T
	router routers.Router
	opts   *openapi3filter.Options

	mu       sync.Mutex
	requests []string // requests that fail the definition
	answers  []string // answers that fail it
	schemas  []string
	checked  int
}

const specHost = "http://vtn.invalid"

func newSpecValidator(t *testing.T, version string) *specValidator {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(fetchSpec(t, version))
	if err != nil {
		t.Fatalf("loading the %s definition: %v", version, err)
	}
	doc.Servers = openapi3.Servers{{URL: specHost}}
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatalf("routing the %s definition: %v", version, err)
	}
	opts := &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc, MultiError: true,
		RegexCompiler: ecmaRegex}
	opts.SchemaValidationOptions = append(opts.SchemaValidationOptions, openapi3.SetSchemaRegexCompiler(ecmaRegex))
	return &specValidator{doc: doc, router: router, opts: opts}
}

// ecmaRegex compiles the definition's patterns as ECMAScript ones (they
// use look-ahead, which Go's regexp lacks).
func ecmaRegex(expr string) (openapi3.RegexMatcher, error) {
	re, err := regexp2.Compile(expr, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	return ecmaMatcher{re}, nil
}

type ecmaMatcher struct{ re *regexp2.Regexp }

func (m ecmaMatcher) MatchString(s string) bool { ok, _ := m.re.MatchString(s); return ok }

func (v *specValidator) note(list *[]string, format string, a ...any) {
	v.mu.Lock()
	*list = append(*list, fmt.Sprintf(format, a...))
	v.mu.Unlock()
}

func (v *specValidator) route(method, path string, query url.Values, ct string, body []byte) (*openapi3filter.RequestValidationInput, error) {
	u := specHost + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	route, params, err := v.router.FindRoute(req)
	if err != nil {
		return nil, err
	}
	return &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route, Options: v.opts}, nil
}

// Schema implements oadr3.Validator.
func (v *specValidator) Schema(name string, body []byte) error {
	ref := v.doc.Components.Schemas[name]
	if ref == nil {
		return nil
	}
	var x any
	if err := json.Unmarshal(body, &x); err != nil {
		v.note(&v.schemas, "%s: not JSON", name)
		return nil
	}
	v.mu.Lock()
	v.checked++
	v.mu.Unlock()
	if err := ref.Value.VisitJSON(x); err != nil {
		v.note(&v.schemas, "%s: %v: %s", name, oneLine(err), clip(body))
	}
	return nil
}

// Request implements oadr3.Validator.
func (v *specValidator) Request(method, path string, query url.Values, ct string, body []byte) error {
	in, err := v.route(method, path, query, ct, body)
	if err != nil {
		v.note(&v.requests, "%s %s: no such operation: %v", method, path, err)
		return nil
	}
	v.mu.Lock()
	v.checked++
	v.mu.Unlock()
	if err := openapi3filter.ValidateRequest(context.Background(), in); err != nil {
		v.note(&v.requests, "%s %s: %v: %s", method, path, oneLine(err), clip(body))
	}
	return nil
}

// Response implements oadr3.Validator.
func (v *specValidator) Response(method, path string, status int, ct string, body []byte) error {
	in, err := v.route(method, path, nil, "", nil)
	if err != nil {
		v.note(&v.answers, "%s %s: no such operation: %v", method, path, err)
		return nil
	}
	v.mu.Lock()
	v.checked++
	v.mu.Unlock()
	h := http.Header{}
	h.Set("Content-Type", ct)
	out := &openapi3filter.ResponseValidationInput{RequestValidationInput: in, Status: status, Header: h,
		Body: io.NopCloser(bytes.NewReader(body)), Options: v.opts}
	if err := openapi3filter.ValidateResponse(context.Background(), out); err != nil {
		v.note(&v.answers, "%s %s %d: %v: %s", method, path, status, oneLine(err), clip(body))
	}
	return nil
}

// report gives the failures and the number of checks.
func (v *specValidator) report() (requests, answers, schemas []string, checked int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.requests...), append([]string(nil), v.answers...), append([]string(nil), v.schemas...), v.checked
}

func clip(b []byte) string {
	if len(b) > 300 {
		return string(b[:300]) + "…"
	}
	return string(b)
}

func oneLine(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 600 {
		s = s[:600] + "…"
	}
	return s
}
