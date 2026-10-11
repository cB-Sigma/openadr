// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr/oadr3"
	"github.com/cB-Sigma/openadr/oadr3/vtn"
)

const base = "/openadr3/3.1.0"

// fixture is a VTN served by httptest with one business-logic client and
// two VEN clients.
type fixture struct {
	t   *testing.T
	v   *vtn.VTN
	srv *httptest.Server
	bl  *oadr3.APIClient
	v1  *oadr3.APIClient
	v2  *oadr3.APIClient
}

func newFixture(t *testing.T, mod func(*vtn.Config)) *fixture {
	t.Helper()
	cfg := vtn.Config{
		BasePath: base,
		Clients: []vtn.Client{
			{ClientID: "bl", Secret: "bl-secret", Role: vtn.RoleBL},
			{ClientID: "ven-a", Secret: "a-secret", Role: vtn.RoleVEN},
			{ClientID: "ven-b", Secret: "b-secret", Role: vtn.RoleVEN},
		},
		Webhooks: vtn.WebhookConfig{AllowHTTP: true, AllowPrivate: true, Backoff: 10 * time.Millisecond},
	}
	if mod != nil {
		mod(&cfg)
	}
	v, err := vtn.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(v)
	t.Cleanup(func() { srv.Close(); _ = v.Close() })
	v.SetPublicURL(srv.URL + base)
	f := &fixture{t: t, v: v, srv: srv}
	mk := func(id, secret string) *oadr3.APIClient {
		return oadr3.NewClient(oadr3.ClientConfig{BaseURL: srv.URL + base, ClientID: id, Secret: secret})
	}
	f.bl, f.v1, f.v2 = mk("bl", "bl-secret"), mk("ven-a", "a-secret"), mk("ven-b", "b-secret")
	return f
}

func (f *fixture) do(c *oadr3.APIClient, method, path string, q url.Values, body any) (oadr3.Object, int) {
	f.t.Helper()
	var out oadr3.Object
	st, err := c.Do(context.Background(), method, path, q, body, &out)
	var he *oadr3.HTTPError
	if err != nil && !errors.As(err, &he) {
		f.t.Fatalf("%s %s: %v", method, path, err)
	}
	return out, st
}

func (f *fixture) must(c *oadr3.APIClient, method, path string, body any, want int) oadr3.Object {
	f.t.Helper()
	o, st := f.do(c, method, path, nil, body)
	if st != want {
		f.t.Fatalf("%s %s: status %d, want %d (%v)", method, path, st, want, o)
	}
	return o
}

func (f *fixture) list(c *oadr3.APIClient, path string, q url.Values) ([]oadr3.Object, int) {
	f.t.Helper()
	var out []oadr3.Object
	st, err := c.Do(context.Background(), http.MethodGet, path, q, nil, &out)
	var he *oadr3.HTTPError
	if err != nil && !errors.As(err, &he) {
		f.t.Fatalf("GET %s: %v", path, err)
	}
	return out, st
}

func program(name string, targets ...string) oadr3.Object {
	o := oadr3.Object{"programName": name}
	if len(targets) > 0 {
		o["targets"] = targets
	}
	return o
}

func event(progID, name string, targets ...string) oadr3.Object {
	o := oadr3.Object{"programID": progID, "eventName": name,
		"intervalPeriod": map[string]any{"start": "2026-10-12T10:00:00Z", "duration": "PT1H"},
		"intervals":      []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "PRICE", "values": []any{0.2}}}}}}
	if len(targets) > 0 {
		o["targets"] = targets
	}
	return o
}

// The token endpoint: discovery, the client-credentials grant in the form
// body and with HTTP Basic, wrong secrets, unknown grants and scopes.
func TestTokenEndpoint(t *testing.T) {
	f := newFixture(t, nil)
	var info map[string]string
	resp, err := http.Get(f.srv.URL + base + "/auth/server")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&info)
	resp.Body.Close()
	if info["tokenURL"] != f.srv.URL+base+"/auth/token" {
		t.Fatalf("tokenURL %q", info["tokenURL"])
	}
	post := func(form url.Values, basicID, basicSecret string) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodPost, info["tokenURL"], strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basicID != "" {
			req.SetBasicAuth(basicID, basicSecret)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m
	}
	st, m := post(url.Values{"grant_type": {"client_credentials"}, "client_id": {"bl"}, "client_secret": {"bl-secret"}}, "", "")
	if st != 200 || m["token_type"] != "Bearer" || m["access_token"] == "" || m["expires_in"].(float64) <= 0 {
		t.Fatalf("form grant: %d %v", st, m)
	}
	st, m = post(url.Values{"grant_type": {"client_credentials"}}, "ven-a", "a-secret")
	if st != 200 || !strings.Contains(m["scope"].(string), vtn.ScopeWriteReports) {
		t.Fatalf("basic grant: %d %v", st, m)
	}
	if st, m = post(url.Values{"grant_type": {"client_credentials"}, "client_id": {"bl"}, "client_secret": {"x"}}, "", ""); st != 401 || m["error"] != "invalid_client" {
		t.Fatalf("wrong secret: %d %v", st, m)
	}
	if st, m = post(url.Values{"grant_type": {"password"}, "client_id": {"bl"}, "client_secret": {"bl-secret"}}, "", ""); st != 400 || m["error"] != "unsupported_grant_type" {
		t.Fatalf("password grant: %d %v", st, m)
	}
	if st, m = post(url.Values{"grant_type": {"client_credentials"}, "scope": {vtn.ScopeWritePrograms}}, "ven-a", "a-secret"); st != 400 || m["error"] != "invalid_scope" {
		t.Fatalf("VEN asking for write_programs: %d %v", st, m)
	}
	// A narrowed token cannot do what its scopes leave out.
	narrow := oadr3.NewClient(oadr3.ClientConfig{BaseURL: f.srv.URL + base, ClientID: "bl", Secret: "bl-secret", Scope: vtn.ScopeReadAll + " " + vtn.ScopeReadTargets})
	if _, st := f.do(narrow, http.MethodPost, "/programs", nil, program("p")); st != http.StatusForbidden {
		t.Fatalf("narrow token wrote a program: %d", st)
	}
	if _, st := f.list(narrow, "/programs", nil); st != 200 {
		t.Fatalf("narrow token read programs: %d", st)
	}
}

// Requests without a token, with a forged one, and with an expired one.
func TestBearerTokens(t *testing.T) {
	now := time.Now()
	var mu sync.Mutex
	f := newFixture(t, func(c *vtn.Config) {
		c.TokenLifetime = time.Minute
		c.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	get := func(auth string) (int, string, oadr3.Object) {
		req, _ := http.NewRequest(http.MethodGet, f.srv.URL+base+"/programs", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var o oadr3.Object
		_ = json.NewDecoder(resp.Body).Decode(&o)
		return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), o
	}
	if st, h, o := get(""); st != 401 || !strings.HasPrefix(h, "Bearer") || o["status"].(float64) != 401 || o["title"] == "" {
		t.Fatalf("no token: %d %q %v", st, h, o)
	}
	tok, err := f.bl.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st, _, _ := get("Bearer " + tok); st != 200 {
		t.Fatalf("good token: %d", st)
	}
	forged := tok[:len(tok)-4] + "AAAA"
	if st, _, _ := get("Bearer " + forged); st != 401 {
		t.Fatalf("forged token: %d", st)
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	if st, _, _ := get("Bearer " + tok); st != 401 {
		t.Fatalf("expired token: %d", st)
	}
}

// Business logic writes programs and events; a VEN may not; names are
// unique; metadata is the VTN's; unknown IDs are 404; bad bodies are 400.
func TestProgramsAndEvents(t *testing.T) {
	f := newFixture(t, nil)
	p := f.must(f.bl, http.MethodPost, "/programs", oadr3.Object{"programName": "p1", "id": "mine", "createdDateTime": "1999-01-01T00:00:00Z"}, 201)
	if p["id"] == "mine" || p["objectType"] != oadr3.TypeProgram || oadr3.Str(p, "createdDateTime") == "1999-01-01T00:00:00Z" || p["modificationDateTime"] == nil {
		t.Fatalf("metadata: %v", p)
	}
	pid := oadr3.Str(p, "id")
	f.must(f.bl, http.MethodPost, "/programs", program("p1"), 409)
	f.must(f.v1, http.MethodPost, "/programs", program("p2"), 403)
	f.must(f.bl, http.MethodPost, "/programs", oadr3.Object{"programName": 7}, 400)
	f.must(f.bl, http.MethodPost, "/events", event("nope", "e"), 400)
	e := f.must(f.bl, http.MethodPost, "/events", event(pid, "e1"), 201)
	eid := oadr3.Str(e, "id")
	f.must(f.v1, http.MethodPost, "/events", event(pid, "e2"), 403)

	// Update keeps createdDateTime and moves modificationDateTime on.
	e2 := event(pid, "e1-renamed")
	u := f.must(f.bl, http.MethodPut, "/events/"+eid, e2, 200)
	if u["createdDateTime"] != e["createdDateTime"] || u["modificationDateTime"] == e["modificationDateTime"] || u["eventName"] != "e1-renamed" {
		t.Fatalf("update: before %v after %v", e, u)
	}
	f.must(f.bl, http.MethodPut, "/events/none", e2, 404)
	f.must(f.bl, http.MethodGet, "/events/"+eid, nil, 200)
	f.must(f.bl, http.MethodDelete, "/events/"+eid, nil, 200)
	f.must(f.bl, http.MethodGet, "/events/"+eid, nil, 404)
	f.must(f.bl, http.MethodGet, "/nothing-here", nil, 404)

	// A body that is not JSON.
	tok, _ := f.bl.Token(context.Background())
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+base+"/programs", strings.NewReader("programName=x"))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("form body: %d", resp.StatusCode)
	}
}

// Targets: a VEN sees an untargeted program, and a targeted one only when
// it asks for a target business logic granted it (through its ven or
// resources); the targets shown are only the ones it matched. Business
// logic sees everything and can filter by targets.
func TestTargetPrivacy(t *testing.T) {
	f := newFixture(t, nil)
	open := f.must(f.bl, http.MethodPost, "/programs", program("open"), 201)
	gold := f.must(f.bl, http.MethodPost, "/programs", program("gold", "group-gold", "zone-1"), 201)
	f.must(f.bl, http.MethodPost, "/programs", program("silver", "group-silver"), 201)

	// ven-a enrols; only business logic may grant targets.
	va := f.must(f.v1, http.MethodPost, "/vens", oadr3.Object{"objectType": "VEN_VEN_REQUEST", "venName": "a", "targets": []string{"group-silver"}}, 201)
	if va["targets"] != nil || va["clientID"] != "ven-a" || va["objectType"] != oadr3.TypeVEN {
		t.Fatalf("VEN granted itself targets: %v", va)
	}
	f.must(f.bl, http.MethodPut, "/vens/"+oadr3.Str(va, "id"), oadr3.Object{"objectType": "BL_VEN_REQUEST", "venName": "a", "clientID": "ven-a", "targets": []string{"group-gold"}}, 200)

	names := func(c *oadr3.APIClient, q url.Values) []string {
		l, st := f.list(c, "/programs", q)
		if st != 200 {
			t.Fatalf("list: %d", st)
		}
		var out []string
		for _, o := range l {
			out = append(out, oadr3.Str(o, "programName")+fmt.Sprint(oadr3.Strs(o["targets"])))
		}
		return out
	}
	if got := fmt.Sprint(names(f.v1, nil)); got != "[open[]]" {
		t.Fatalf("ven-a without targets: %s", got)
	}
	if got := fmt.Sprint(names(f.v1, url.Values{"targets": {"group-gold", "group-silver"}})); got != "[open[] gold[group-gold]]" {
		t.Fatalf("ven-a with targets: %s", got)
	}
	if got := fmt.Sprint(names(f.v2, url.Values{"targets": {"group-gold"}})); got != "[open[]]" {
		t.Fatalf("ven-b (no ven object): %s", got)
	}
	if got := fmt.Sprint(names(f.bl, nil)); got != "[open[] gold[group-gold zone-1] silver[group-silver]]" {
		t.Fatalf("business logic: %s", got)
	}
	if got := fmt.Sprint(names(f.bl, url.Values{"targets": {"group-silver"}})); got != "[silver[group-silver]]" {
		t.Fatalf("business logic filtered: %s", got)
	}
	// One object: hidden objects are not found.
	f.must(f.v2, http.MethodGet, "/programs/"+oadr3.Str(gold, "id"), nil, 404)
	f.must(f.v2, http.MethodGet, "/programs/"+oadr3.Str(open, "id"), nil, 200)
	if o, st := f.do(f.v1, http.MethodGet, "/programs/"+oadr3.Str(gold, "id"), url.Values{"targets": {"group-gold"}}, nil); st != 200 || fmt.Sprint(o["targets"]) != "[group-gold]" {
		t.Fatalf("ven-a reads gold: %d %v", st, o)
	}

	// A resource's targets count as granted too.
	f.must(f.bl, http.MethodPost, "/resources", oadr3.Object{"objectType": "BL_RESOURCE_REQUEST", "resourceName": "meter", "venID": va["id"], "clientID": "ven-a", "targets": []string{"zone-1"}}, 201)
	if got := fmt.Sprint(names(f.v1, url.Values{"targets": {"zone-1"}})); got != "[open[] gold[zone-1]]" {
		t.Fatalf("ven-a by its resource's target: %s", got)
	}
}

// VEN-owned objects (vens, resources, reports, subscriptions) are visible
// only to their client and to business logic.
func TestOwnedObjectPrivacy(t *testing.T) {
	f := newFixture(t, nil)
	p := f.must(f.bl, http.MethodPost, "/programs", program("p"), 201)
	e := f.must(f.bl, http.MethodPost, "/events", event(oadr3.Str(p, "id"), "e"), 201)
	va := f.must(f.v1, http.MethodPost, "/vens", oadr3.Object{"objectType": "VEN_VEN_REQUEST", "venName": "a"}, 201)
	vb := f.must(f.v2, http.MethodPost, "/vens", oadr3.Object{"objectType": "VEN_VEN_REQUEST", "venName": "b"}, 201)
	f.must(f.v2, http.MethodPost, "/vens", oadr3.Object{"objectType": "VEN_VEN_REQUEST", "venName": "a"}, 409)
	f.must(f.v1, http.MethodPost, "/vens", oadr3.Object{"objectType": "BL_VEN_REQUEST", "venName": "c", "clientID": "x"}, 403)
	ra := f.must(f.v1, http.MethodPost, "/resources", oadr3.Object{"objectType": "VEN_RESOURCE_REQUEST", "resourceName": "r", "venID": va["id"]}, 201)
	f.must(f.v1, http.MethodPost, "/resources", oadr3.Object{"objectType": "VEN_RESOURCE_REQUEST", "resourceName": "r", "venID": va["id"]}, 409)
	f.must(f.v2, http.MethodPost, "/resources", oadr3.Object{"objectType": "VEN_RESOURCE_REQUEST", "resourceName": "r", "venID": va["id"]}, 403)
	f.must(f.v2, http.MethodPost, "/resources", oadr3.Object{"objectType": "VEN_RESOURCE_REQUEST", "resourceName": "r", "venID": vb["id"]}, 201)
	rep := f.must(f.v1, http.MethodPost, "/reports", oadr3.Object{"eventID": e["id"], "clientName": "a",
		"resources": []any{map[string]any{"resourceName": "r", "intervals": []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "USAGE", "values": []any{1.5}}}}}}}}, 201)
	if rep["clientID"] != "ven-a" {
		t.Fatalf("report owner: %v", rep)
	}
	f.must(f.v2, http.MethodGet, "/vens/"+oadr3.Str(va, "id"), nil, 404)
	f.must(f.v2, http.MethodGet, "/resources/"+oadr3.Str(ra, "id"), nil, 404)
	f.must(f.v2, http.MethodGet, "/reports/"+oadr3.Str(rep, "id"), nil, 404)
	f.must(f.v2, http.MethodPut, "/reports/"+oadr3.Str(rep, "id"), oadr3.Object{"eventID": e["id"], "clientName": "b", "resources": []any{}}, 404)
	f.must(f.v2, http.MethodDelete, "/vens/"+oadr3.Str(va, "id"), nil, 404)
	f.must(f.bl, http.MethodGet, "/reports/"+oadr3.Str(rep, "id"), nil, 200)
	f.must(f.bl, http.MethodPost, "/reports", oadr3.Object{"eventID": e["id"], "clientName": "bl", "resources": []any{}}, 403)
	l, _ := f.list(f.v2, "/vens", nil)
	if len(l) != 1 || l[0]["venName"] != "b" {
		t.Fatalf("ven-b lists vens: %v", l)
	}
	l, _ = f.list(f.bl, "/resources", url.Values{"venID": {oadr3.Str(va, "id")}})
	if len(l) != 1 {
		t.Fatalf("resources of ven a: %v", l)
	}
	l, _ = f.list(f.bl, "/reports", url.Values{"programID": {oadr3.Str(p, "id")}})
	if len(l) != 1 {
		t.Fatalf("reports of the program: %v", l)
	}
	// Deleting a ven deletes its resources.
	f.must(f.v1, http.MethodDelete, "/vens/"+oadr3.Str(va, "id"), nil, 200)
	f.must(f.bl, http.MethodGet, "/resources/"+oadr3.Str(ra, "id"), nil, 404)
}

// Paging (skip, limit, the maximum page), filters and unknown parameters.
func TestPagingAndFilters(t *testing.T) {
	f := newFixture(t, nil)
	p := f.must(f.bl, http.MethodPost, "/programs", program("p"), 201)
	q := f.must(f.bl, http.MethodPost, "/programs", program("q"), 201)
	for i := range 55 {
		pid := p["id"]
		if i%5 == 0 {
			pid = q["id"]
		}
		f.must(f.bl, http.MethodPost, "/events", event(fmt.Sprint(pid), fmt.Sprintf("e%02d", i)), 201)
	}
	l, _ := f.list(f.bl, "/events", nil)
	if len(l) != oadr3.MaxLimit {
		t.Fatalf("default page: %d", len(l))
	}
	l, _ = f.list(f.bl, "/events", url.Values{"skip": {"50"}, "limit": {"10"}})
	if len(l) != 5 || l[0]["eventName"] != "e50" {
		t.Fatalf("last page: %v", l)
	}
	if _, st := f.list(f.bl, "/events", url.Values{"limit": {"51"}}); st != 400 {
		t.Fatalf("limit 51: %d", st)
	}
	if _, st := f.list(f.bl, "/events", url.Values{"skip": {"-1"}}); st != 400 {
		t.Fatalf("skip -1: %d", st)
	}
	if _, st := f.list(f.bl, "/events", url.Values{"color": {"red"}}); st != 400 {
		t.Fatalf("unknown parameter: %d", st)
	}
	all, err := f.bl.All(context.Background(), "/events", url.Values{"programID": {oadr3.Str(q, "id")}})
	if err != nil || len(all) != 11 {
		t.Fatalf("events of q: %d %v", len(all), err)
	}
	// active=true leaves out events that are over.
	f.must(f.bl, http.MethodPost, "/events", oadr3.Object{"programID": p["id"], "eventName": "old",
		"intervalPeriod": map[string]any{"start": "2020-01-01T00:00:00Z", "duration": "PT1H"},
		"intervals":      []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "PRICE", "values": []any{1}}}}}}, 201)
	all, _ = f.bl.All(context.Background(), "/events", url.Values{"active": {"true"}})
	for _, e := range all {
		if e["eventName"] == "old" {
			t.Fatal("active=true gave a past event")
		}
	}
	all, _ = f.bl.All(context.Background(), "/events", url.Values{"active": {"false"}})
	if len(all) != 56 {
		t.Fatalf("active=false: %d", len(all))
	}
}

// webhook is a test callback receiver.
type webhook struct {
	srv   *httptest.Server
	mu    sync.Mutex
	notes []map[string]any
	auth  []string
	sigs  []string
	ids   []string
	fail  int // answer 500 this many times first
	echo  bool
	body  [][]byte
}

func newWebhook(t *testing.T) *webhook {
	w := &webhook{echo: true}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		defer w.mu.Unlock()
		if r.Method == http.MethodGet {
			if w.echo {
				_, _ = io.WriteString(rw, r.URL.Query().Get("echo"))
			}
			return
		}
		if w.fail > 0 {
			w.fail--
			rw.WriteHeader(500)
			return
		}
		b, _ := io.ReadAll(r.Body)
		var n map[string]any
		_ = json.Unmarshal(b, &n)
		w.notes = append(w.notes, n)
		w.body = append(w.body, b)
		w.auth = append(w.auth, r.Header.Get("Authorization"))
		w.sigs = append(w.sigs, r.Header.Get(vtn.SignatureHeader))
		w.ids = append(w.ids, r.Header.Get(vtn.NotificationIDHeader))
	}))
	t.Cleanup(w.srv.Close)
	return w
}

func (w *webhook) wait(t *testing.T, n int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		w.mu.Lock()
		got := append([]map[string]any(nil), w.notes...)
		w.mu.Unlock()
		if len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("got fewer than %d notifications", n)
	return nil
}

// Subscriptions by webhook: the echo check, notifications with the
// subscription's bearer token, retries after failures, privacy of what a
// VEN is notified about, the signature header and program filtering.
func TestWebhooks(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	f := newFixture(t, func(c *vtn.Config) { c.Webhooks.SigningKey = key })
	hookA, hookBL := newWebhook(t), newWebhook(t)
	hookA.fail = 2

	p := f.must(f.bl, http.MethodPost, "/programs", program("p"), 201)
	pid := oadr3.Str(p, "id")
	va := f.must(f.v1, http.MethodPost, "/vens", oadr3.Object{"objectType": "VEN_VEN_REQUEST", "venName": "a"}, 201)
	f.must(f.bl, http.MethodPut, "/vens/"+oadr3.Str(va, "id"), oadr3.Object{"objectType": "BL_VEN_REQUEST", "venName": "a", "clientID": "ven-a", "targets": []string{"g1"}}, 200)

	// The echo check refuses a callback that does not answer it.
	bad := newWebhook(t)
	bad.echo = false
	sub := func(c *oadr3.APIClient, url, bearer string, objects []string, targets ...string) oadr3.Object {
		o := oadr3.Object{"clientName": "c", "programID": pid, "objectOperations": []any{map[string]any{
			"objects": objects, "operations": []string{"CREATE", "UPDATE", "DELETE"}, "callbackUrl": url, "bearerToken": bearer}}}
		if len(targets) > 0 {
			o["targets"] = targets
		}
		return o
	}
	f.must(f.v1, http.MethodPost, "/subscriptions", sub(f.v1, bad.srv.URL+"/cb", "", []string{"EVENT"}), 400)

	s := f.must(f.v1, http.MethodPost, "/subscriptions", sub(f.v1, hookA.srv.URL+"/cb", "tok-a", []string{"EVENT"}, "g1"), 201)
	if s["clientID"] != "ven-a" {
		t.Fatalf("subscription owner: %v", s)
	}
	f.must(f.bl, http.MethodPost, "/subscriptions", sub(f.bl, hookBL.srv.URL+"/cb", "tok-bl", []string{"EVENT", "PROGRAM"}), 201)

	f.must(f.bl, http.MethodPost, "/events", event(pid, "hidden", "g2"), 201)
	ev := f.must(f.bl, http.MethodPost, "/events", event(pid, "shown", "g1", "g2"), 201)
	f.must(f.bl, http.MethodDelete, "/events/"+oadr3.Str(ev, "id"), nil, 200)

	got := hookA.wait(t, 2)
	time.Sleep(100 * time.Millisecond)
	got = hookA.wait(t, 2)
	if len(got) != 2 {
		t.Fatalf("ven-a got %d notifications: %v", len(got), got)
	}
	for i, op := range []string{"CREATE", "DELETE"} {
		n := got[i]
		obj, _ := n["object"].(map[string]any)
		if n["operation"] != op || n["objectType"] != oadr3.TypeEvent || obj["eventName"] != "shown" || fmt.Sprint(obj["targets"]) != "[g1]" {
			t.Fatalf("notification %d: %v", i, n)
		}
	}
	hookA.mu.Lock()
	if hookA.auth[0] != "Bearer tok-a" {
		t.Fatalf("bearer: %q", hookA.auth[0])
	}
	if !vtn.VerifySignature(key, hookA.body[0], hookA.sigs[0], time.Now(), time.Minute) ||
		vtn.VerifySignature([]byte("another key, 32 bytes long......"), hookA.body[0], hookA.sigs[0], time.Now(), time.Minute) ||
		vtn.VerifySignature(key, append(hookA.body[0], ' '), hookA.sigs[0], time.Now(), time.Minute) {
		t.Fatalf("signature %q", hookA.sigs[0])
	}
	ts := strings.TrimPrefix(strings.Split(hookA.sigs[0], ",")[0], "t=")
	m := hmac.New(sha256.New, key)
	m.Write([]byte(ts + "."))
	m.Write(hookA.body[0])
	if want := "sha256=" + hex.EncodeToString(m.Sum(nil)); !strings.Contains(hookA.sigs[0], want) {
		t.Fatalf("signature %q, want %q in it", hookA.sigs[0], want)
	}
	if hookA.ids[0] == "" || hookA.ids[0] == hookA.ids[1] {
		t.Fatalf("notification IDs: %v", hookA.ids)
	}
	hookA.mu.Unlock()
	// Business logic sees all three event changes (and no program changes
	// happened after it subscribed).
	if n := len(hookBL.wait(t, 3)); n != 3 {
		t.Fatalf("business logic got %d", n)
	}
}

// A callback that keeps failing is marked broken after BrokenAfter
// failures and skipped until its subscription is written again.
func TestWebhookBroken(t *testing.T) {
	var errs []error
	var mu sync.Mutex
	f := newFixture(t, func(c *vtn.Config) {
		c.Webhooks.Retries = 1
		c.Webhooks.BrokenAfter = 2
		c.OnDeliveryError = func(d vtn.Delivery, err error) { mu.Lock(); errs = append(errs, err); mu.Unlock() }
	})
	h := newWebhook(t)
	p := f.must(f.bl, http.MethodPost, "/programs", program("p"), 201)
	so := oadr3.Object{"clientName": "c", "objectOperations": []any{map[string]any{
		"objects": []string{"EVENT"}, "operations": []string{"CREATE"}, "callbackUrl": h.srv.URL}}}
	s := f.must(f.bl, http.MethodPost, "/subscriptions", so, 201)
	h.mu.Lock()
	h.fail = 1000
	h.mu.Unlock()
	for i := range 4 {
		f.must(f.bl, http.MethodPost, "/events", event(oadr3.Str(p, "id"), fmt.Sprint(i)), 201)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(errs)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	n := len(errs)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("%d failed deliveries, want 2 then skipped", n)
	}
	if st := f.v.Status(); len(st.BrokenCallbacks) != 1 {
		t.Fatalf("status: %+v", st)
	}
	h.mu.Lock()
	h.fail = 0
	h.mu.Unlock()
	f.must(f.bl, http.MethodPut, "/subscriptions/"+oadr3.Str(s, "id"), so, 200)
	f.must(f.bl, http.MethodPost, "/events", event(oadr3.Str(p, "id"), "after"), 201)
	h.wait(t, 1)
}

// The in-process business-logic API and the change hook.
func TestBusinessLogicAPI(t *testing.T) {
	var changes []string
	var mu sync.Mutex
	f := newFixture(t, func(c *vtn.Config) {
		c.OnChange = func(ch vtn.Change) {
			mu.Lock()
			changes = append(changes, ch.Operation+" "+ch.ObjectType+" "+ch.ClientID)
			mu.Unlock()
		}
	})
	ctx := context.Background()
	p, err := f.v.Create(ctx, oadr3.TypeProgram, program("p"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.v.Create(ctx, oadr3.TypeProgram, program("p")); !vtn.IsStatus(err, 409) {
		t.Fatalf("duplicate: %v", err)
	}
	e, err := f.v.Create(ctx, oadr3.TypeEvent, event(oadr3.Str(p, "id"), "e"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.v.Get(ctx, oadr3.TypeEvent, oadr3.Str(e, "id")); err != nil || got["eventName"] != "e" {
		t.Fatalf("get: %v %v", got, err)
	}
	f.must(f.v1, http.MethodPost, "/vens", oadr3.Object{"objectType": "VEN_VEN_REQUEST", "venName": "a"}, 201)
	if l, err := f.v.List(ctx, oadr3.TypeVEN); err != nil || len(l) != 1 {
		t.Fatalf("list: %v %v", l, err)
	}
	if _, err := f.v.Delete(ctx, oadr3.TypeEvent, oadr3.Str(e, "id")); err != nil {
		t.Fatal(err)
	}
	want := "CREATE PROGRAM " + vtn.InternalClientID + ",CREATE EVENT " + vtn.InternalClientID + ",CREATE VEN ven-a,DELETE EVENT " + vtn.InternalClientID
	var got string
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		mu.Lock()
		got = strings.Join(changes, ",")
		mu.Unlock()
		if got == want {
			return
		}
	}
	t.Fatalf("changes: %s", got)
}

// A custom store sees every write; objects survive a new VTN on the same
// store.
func TestStorePersistence(t *testing.T) {
	st := vtn.NewMemoryStore()
	f := newFixture(t, func(c *vtn.Config) { c.Store = st })
	p := f.must(f.bl, http.MethodPost, "/programs", program("kept"), 201)
	v2, err := vtn.New(vtn.Config{Store: st, Clients: []vtn.Client{{ClientID: "bl", Secret: "s", Role: vtn.RoleBL}}})
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	got, err := v2.Get(context.Background(), oadr3.TypeProgram, oadr3.Str(p, "id"))
	if err != nil || got["programName"] != "kept" {
		t.Fatalf("from the store: %v %v", got, err)
	}
	if _, err := st.Get(context.Background(), oadr3.TypeProgram, "nope"); !errors.Is(err, vtn.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
}

// Anonymous reads of programs and events, when allowed.
func TestAnonymousRead(t *testing.T) {
	f := newFixture(t, func(c *vtn.Config) { c.AnonymousRead = true })
	f.must(f.bl, http.MethodPost, "/programs", program("tariff"), 201)
	f.must(f.bl, http.MethodPost, "/programs", program("secret", "g"), 201)
	anon := oadr3.NewClient(oadr3.ClientConfig{BaseURL: f.srv.URL + base})
	l, st := f.list(anon, "/programs", nil)
	if st != 200 || len(l) != 1 || l[0]["programName"] != "tariff" {
		t.Fatalf("anonymous: %d %v", st, l)
	}
	if _, st := f.list(anon, "/vens", nil); st != 401 {
		t.Fatalf("anonymous vens: %d", st)
	}
}

// MQTT notifier: topics published per change, the topic listing and the
// subscribe rule.
func TestMQTTNotifier(t *testing.T) {
	pub := &fakePublisher{}
	f := newFixture(t, func(c *vtn.Config) {
		c.MQTT = &vtn.MQTTConfig{Publisher: pub, URIs: []string{"mqtts://broker:8883"}}
	})
	p := f.must(f.bl, http.MethodPost, "/programs", program("p", "g1"), 201)
	va := f.must(f.v1, http.MethodPost, "/vens", oadr3.Object{"objectType": "VEN_VEN_REQUEST", "venName": "a"}, 201)
	f.must(f.bl, http.MethodPut, "/vens/"+oadr3.Str(va, "id"), oadr3.Object{"objectType": "BL_VEN_REQUEST", "venName": "a", "clientID": "ven-a", "targets": []string{"g1"}}, 200)
	f.must(f.bl, http.MethodPost, "/events", event(oadr3.Str(p, "id"), "e", "g1"), 201)
	topics := pub.topics()
	want := []string{"programs/create", "events/create", "programs/" + oadr3.Str(p, "id") + "/events/create", "vens/" + oadr3.Str(va, "id") + "/events/create"}
	for _, w := range want {
		found := false
		for _, tp := range topics {
			found = found || tp == w
		}
		if !found {
			t.Fatalf("no publication on %s in %v", w, topics)
		}
	}
	n := f.must(f.v1, http.MethodGet, "/notifiers", nil, 200)
	if n["WEBHOOK"] != true || n["MQTT"] == nil {
		t.Fatalf("notifiers: %v", n)
	}
	tp := f.must(f.v1, http.MethodGet, "/notifiers/mqtt/topics/vens/"+oadr3.Str(va, "id")+"/events", nil, 200)
	if fmt.Sprint(tp["topics"]) == "" {
		t.Fatalf("topics: %v", tp)
	}
	f.must(f.v2, http.MethodGet, "/notifiers/mqtt/topics/vens/"+oadr3.Str(va, "id")+"/events", nil, 404)
	if !f.v.MQTTAllowed("ven-a", "vens/"+oadr3.Str(va, "id")+"/events/+", false) || f.v.MQTTAllowed("ven-b", "vens/"+oadr3.Str(va, "id")+"/events/+", false) ||
		f.v.MQTTAllowed("bl", "programs/create", true) || !f.v.MQTTAllowed("bl", "programs/create", false) {
		t.Fatal("MQTT subscribe rule")
	}
	tok, _ := f.v1.Token(context.Background())
	if id, ok := f.v.MQTTLogin("ven-a", tok); !ok || id != "ven-a" {
		t.Fatal("MQTT login with a token")
	}
	if _, ok := f.v.MQTTLogin("ven-b", tok); ok {
		t.Fatal("MQTT login under another name")
	}
}

type fakePublisher struct {
	mu sync.Mutex
	ts []string
}

func (p *fakePublisher) Publish(_ context.Context, topic string, _ []byte) error {
	p.mu.Lock()
	p.ts = append(p.ts, topic)
	p.mu.Unlock()
	return nil
}

func (p *fakePublisher) topics() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.ts...)
}

// OpenADR 3.0: targets as lists of type and values, targetType and
// targetValues in queries, ven and resource requests without a request
// form, and the 3.0 scopes.
func TestVersion30(t *testing.T) {
	f := newFixture(t, func(c *vtn.Config) { c.Version = vtn.Version30 })
	tok, err := f.v1.Token(context.Background())
	if err != nil || tok == "" {
		t.Fatal(err)
	}
	g := []any{map[string]any{"type": "GROUP", "values": []any{"gold"}}}
	p := f.must(f.bl, http.MethodPost, "/programs", oadr3.Object{"programName": "p", "targets": g}, 201)
	if fmt.Sprint(p["targets"]) != "[map[type:GROUP values:[gold]]]" {
		t.Fatalf("3.0 targets: %v", p["targets"])
	}
	f.must(f.bl, http.MethodPost, "/programs", oadr3.Object{"programName": "q"}, 201)
	va := f.must(f.v1, http.MethodPost, "/vens", oadr3.Object{"venName": "a"}, 201)
	f.must(f.bl, http.MethodPut, "/vens/"+oadr3.Str(va, "id"), oadr3.Object{"venName": "a", "targets": g}, 200)
	l, st := f.list(f.v1, "/programs", url.Values{"targetType": {"GROUP"}, "targetValues": {"gold"}})
	if st != 200 || len(l) != 2 {
		t.Fatalf("3.0 VEN query: %d %v", st, l)
	}
	l, _ = f.list(f.v1, "/programs", nil)
	if len(l) != 1 {
		t.Fatalf("3.0 VEN without targets: %v", l)
	}
	f.must(f.v1, http.MethodPost, "/resources", oadr3.Object{"resourceName": "r", "venID": va["id"]}, 201)
}

// EventsByPriority lists events most urgent first, then newest first.
func TestEventOrder(t *testing.T) {
	f := newFixture(t, func(c *vtn.Config) { c.EventOrder = vtn.EventsByPriority })
	p := f.must(f.bl, http.MethodPost, "/programs", program("p"), 201)
	for i, prio := range []any{nil, 5, 1, nil} {
		e := event(oadr3.Str(p, "id"), fmt.Sprint(i))
		if prio != nil {
			e["priority"] = prio
		}
		f.must(f.bl, http.MethodPost, "/events", e, 201)
	}
	l, _ := f.list(f.bl, "/events", nil)
	var got []string
	for _, e := range l {
		got = append(got, oadr3.Str(e, "eventName"))
	}
	if fmt.Sprint(got) != "[2 1 3 0]" {
		t.Fatalf("order: %v", got)
	}
	if _, err := vtn.New(vtn.Config{AnonymousRead: true, EventOrder: "random"}); err == nil {
		t.Fatal("an unknown order was accepted")
	}
}

// Business logic writing a resource without a clientID gets the ven's.
func TestResourceClientIDFromVen(t *testing.T) {
	f := newFixture(t, nil)
	ven := f.must(f.bl, http.MethodPost, "/vens", oadr3.Object{"objectType": "BL_VEN_REQUEST", "venName": "a", "clientID": "ven-a"}, 201)
	r := f.must(f.bl, http.MethodPost, "/resources", oadr3.Object{"objectType": "BL_RESOURCE_REQUEST", "resourceName": "r", "venID": ven["id"]}, 201)
	if r["clientID"] != "ven-a" {
		t.Fatalf("resource: %v", r)
	}
	f.must(f.v1, http.MethodGet, "/resources/"+oadr3.Str(r, "id"), nil, 200)
}

// Many clients at once: unique names hold, every write is notified, and
// the race detector sees no unguarded state.
func TestConcurrentClients(t *testing.T) {
	f := newFixture(t, nil)
	h := newWebhook(t)
	f.must(f.bl, http.MethodPost, "/subscriptions", oadr3.Object{"clientName": "c", "objectOperations": []any{map[string]any{
		"objects": []string{"PROGRAM"}, "operations": []string{"CREATE"}, "callbackUrl": h.srv.URL}}}, 201)
	var wg sync.WaitGroup
	var created atomic32
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 10 {
				// Half the names collide across goroutines.
				name := fmt.Sprintf("p-%d-%d", i%4, j)
				var o oadr3.Object
				st, _ := f.bl.Do(context.Background(), http.MethodPost, "/programs", nil, program(name), &o)
				if st == 201 {
					created.add()
				} else if st != 409 {
					t.Errorf("status %d", st)
				}
				_, _ = f.list(f.v1, "/programs", nil)
			}
		}()
	}
	wg.Wait()
	if n := created.get(); n != 40 {
		t.Fatalf("%d programs created, want 40 (unique names)", n)
	}
	if got := len(h.wait(t, 40)); got != 40 {
		t.Fatalf("%d notifications", got)
	}
}

type atomic32 struct {
	mu sync.Mutex
	n  int
}

func (a *atomic32) add() { a.mu.Lock(); a.n++; a.mu.Unlock() }
func (a *atomic32) get() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.n
}

// A store that fails gives a 500 problem without its error text, and no
// notification or change.
func TestStoreFailure(t *testing.T) {
	st := &failingStore{MemoryStore: vtn.NewMemoryStore()}
	changes := 0
	var mu sync.Mutex
	f := newFixture(t, func(c *vtn.Config) {
		c.Store = st
		c.OnChange = func(vtn.Change) { mu.Lock(); changes++; mu.Unlock() }
	})
	st.fail = true
	o := f.must(f.bl, http.MethodPost, "/programs", program("p"), 500)
	if strings.Contains(fmt.Sprint(o), "disk on fire") {
		t.Fatalf("the store's error leaked: %v", o)
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if changes != 0 {
		t.Fatal("a failed write was reported as a change")
	}
}

type failingStore struct {
	*vtn.MemoryStore
	fail bool
}

func (s *failingStore) Put(ctx context.Context, typ string, o oadr3.Object) error {
	if s.fail {
		return errors.New("disk on fire")
	}
	return s.MemoryStore.Put(ctx, typ, o)
}

// The OpenAPI validator hook sees every request and answer.
func TestValidatorHook(t *testing.T) {
	val := &recordingValidator{}
	f := newFixture(t, func(c *vtn.Config) { c.Validator = val })
	f.must(f.bl, http.MethodPost, "/programs", program("p"), 201)
	val.mu.Lock()
	req, resp := val.req, val.resp
	val.refuse = true
	val.mu.Unlock()
	if req == 0 || resp == 0 {
		t.Fatalf("validator calls: %d requests, %d answers", req, resp)
	}
	f.must(f.bl, http.MethodPost, "/programs", program("q"), 400)
}

type recordingValidator struct {
	mu        sync.Mutex
	req, resp int
	refuse    bool
}

func (v *recordingValidator) Schema(string, []byte) error { return nil }
func (v *recordingValidator) Request(method, path string, _ url.Values, _ string, _ []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.req++
	if v.refuse && method == http.MethodPost && path == "/programs" {
		return errors.New("refused")
	}
	return nil
}
func (v *recordingValidator) Response(string, string, int, string, []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.resp++
	return nil
}
