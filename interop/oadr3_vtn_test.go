// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr/oadr3"
	"github.com/cB-Sigma/openadr/oadr3/vtn"
)

// imageOpenLEADRRSClient holds openleadr-rs's client library and its
// integration tests (peer/openleadr-rs-client).
const imageOpenLEADRRSClient = "sigma-openadr-interop:openleadr-rs-client-0.2.6"

// needSpec skips unless the interop tests are on (they fetch the
// OpenAPI definition; Docker is not needed).
func needSpec(t *testing.T) {
	t.Helper()
	if os.Getenv(envVar) != "1" {
		t.Skip("set " + envVar + "=1 to run the interop tests")
	}
}

// knownDefinitionDefect says whether a failed check is one the OpenADR
// 3.1.0 definition makes unavoidable: its ven and resource schemas are
// allOf objectMetadata (objectType one of the object types) and the
// BL_*_REQUEST forms (objectType BL_VEN_REQUEST or BL_RESOURCE_REQUEST),
// which no object can satisfy at once.
func knownDefinitionDefect(s string) bool {
	s = listIndex.ReplaceAllString(s, "")
	return (strings.Contains(s, " /vens") || strings.Contains(s, " /resources")) &&
		strings.Count(s, "Error at") == strings.Count(s, `Error at "/objectType"`) && strings.Contains(s, `Error at "/objectType"`) &&
		strings.Contains(s, `["BL_`)
}

// listIndex is the position of a list element in a validation error.
var listIndex = regexp.MustCompile(`Error at "/\d+": `)

// checkSpec fails the test for answers (ours) that fail the definition,
// other than the known defect, and logs the rest.
func checkSpec(t *testing.T, v *specValidator, clientIsOurs bool) {
	t.Helper()
	reqs, answers, schemas, checked := v.report()
	var ours []string
	defects := 0
	for _, a := range append(answers, schemas...) {
		if knownDefinitionDefect(a) {
			if defects == 0 {
				t.Logf("example of the definition's ven/resource objectType defect: %s", a)
			}
			defects++
			continue
		}
		ours = append(ours, a)
	}
	var theirs []string
	for _, r := range reqs {
		if clientIsOurs {
			ours = append(ours, "request: "+r)
		} else {
			theirs = append(theirs, r)
		}
	}
	if len(ours) > 0 {
		t.Errorf("%d of our messages fail the OpenAPI definition:\n%s", len(ours), strings.Join(ours, "\n"))
	}
	t.Logf("OpenAPI checks: %d; answers failing only through the ven/resource objectType defect of the definition: %d", checked, defects)
	seen := map[string]bool{}
	for _, r := range theirs {
		k := r
		if i := strings.Index(r, ": "); i > 0 && len(r) > 200 {
			k = r[:200]
		}
		if !seen[k] {
			seen[k] = true
			t.Logf("the peer's request fails the definition: %s", r)
		}
	}
	if checked == 0 {
		t.Fatal("nothing was checked against the definition")
	}
}

// listenVTN serves h on a free port of every interface (a container
// reaches it through host.docker.internal) and gives the port.
func listenVTN(t *testing.T, h http.Handler) int {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port
}

// hook is a webhook receiver that answers the echo check and keeps what
// it gets.
type hook struct {
	mu    sync.Mutex
	notes [][]byte
	auth  []string
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, r.URL.Query().Get("echo"))
		return
	}
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.notes = append(h.notes, b)
	h.auth = append(h.auth, r.Header.Get("Authorization"))
	h.mu.Unlock()
}

func (h *hook) wait(t *testing.T, n int) [][]byte {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		h.mu.Lock()
		got := append([][]byte(nil), h.notes...)
		h.mu.Unlock()
		if len(got) >= n {
			return got
		}
	}
	t.Fatalf("fewer than %d notifications", n)
	return nil
}

// Our OpenADR 3.1 client against our VTN, with both ends checked against
// the OpenADR 3.1.0 OpenAPI definition: tokens, every object type,
// targets and privacy, paging, errors, and a webhook subscription whose
// notifications are checked against the definition's notification schema.
func TestOurClientAgainstOurVTN31(t *testing.T) {
	needSpec(t)
	val := newSpecValidator(t, "3.1.0")
	v, err := vtn.New(vtn.Config{
		Clients: []vtn.Client{{ClientID: "bl", Secret: "bl-secret", Role: vtn.RoleBL},
			{ClientID: "ven", Secret: "ven-secret", Role: vtn.RoleVEN}},
		Validator: val,
		Webhooks:  vtn.WebhookConfig{AllowHTTP: true, AllowPrivate: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	port := listenVTN(t, v)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	v.SetPublicURL(base)
	h := &hook{}
	hport := listenVTN(t, h)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	bl := oadr3.NewClient(oadr3.ClientConfig{BaseURL: base, ClientID: "bl", Secret: "bl-secret", Validator: val})
	ven := oadr3.NewClient(oadr3.ClientConfig{BaseURL: base, ClientID: "ven", Secret: "ven-secret", Validator: val})
	do := func(c *oadr3.APIClient, method, path string, body any, want int) oadr3.Object {
		t.Helper()
		var out oadr3.Object
		st, err := c.Do(ctx, method, path, nil, body, &out)
		var he *oadr3.HTTPError
		if err != nil && !errors.As(err, &he) {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		if st != want {
			t.Fatalf("%s %s: %d, want %d (%v)", method, path, st, want, err)
		}
		return out
	}

	var venObj oadr3.Object
	if _, err := ven.Do(ctx, http.MethodPost, "/vens", nil, oadr3.Object{"objectType": "VEN_VEN_REQUEST", "venName": "site-1"}, &venObj); err != nil {
		t.Fatal(err)
	}
	venID := oadr3.Str(venObj, "id")
	do(bl, http.MethodPut, "/vens/"+venID, oadr3.Object{"objectType": "BL_VEN_REQUEST", "venName": "site-1", "clientID": "ven", "targets": []string{"group-1"}}, 200)
	do(ven, http.MethodPost, "/resources", oadr3.Object{"objectType": "VEN_RESOURCE_REQUEST", "resourceName": "meter-1", "venID": venID}, 201)
	do(ven, http.MethodPost, "/subscriptions", oadr3.Object{"clientName": "site-1", "targets": []string{"group-1"}, "objectOperations": []any{map[string]any{
		"objects": []string{"EVENT", "PROGRAM"}, "operations": []string{"CREATE", "UPDATE", "DELETE"},
		"callbackUrl": fmt.Sprintf("http://127.0.0.1:%d/cb", hport), "bearerToken": "hook-token"}}}, 201)

	prog := do(bl, http.MethodPost, "/programs", oadr3.Object{"programName": "tariff", "targets": []string{"group-1"},
		"payloadDescriptors": []any{map[string]any{"objectType": "EVENT_PAYLOAD_DESCRIPTOR", "payloadType": "PRICE", "units": "KWH", "currency": "INR"}}}, 201)
	do(bl, http.MethodPost, "/programs", oadr3.Object{"programName": "tariff"}, 409)
	do(ven, http.MethodPost, "/programs", oadr3.Object{"programName": "x"}, 403)
	start := time.Now().UTC().Truncate(time.Second)
	ev := do(bl, http.MethodPost, "/events", oadr3.Object{"programID": prog["id"], "eventName": "peak", "targets": []string{"group-1", "group-2"},
		"intervalPeriod": map[string]any{"start": start.Format(time.RFC3339), "duration": "PT1H"},
		"intervals":      []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "PRICE", "values": []any{9.5}}}}}}, 201)
	for i := range oadr3.MaxLimit + 2 {
		do(bl, http.MethodPost, "/events", oadr3.Object{"programID": prog["id"], "eventName": fmt.Sprintf("bulk-%d", i),
			"intervals": []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "PRICE", "values": []any{1}}}}}}, 201)
	}
	all, err := bl.All(ctx, "/events", nil)
	if err != nil || len(all) != oadr3.MaxLimit+3 {
		t.Fatalf("all events: %d, %v", len(all), err)
	}
	seen, err := ven.All(ctx, "/events", url.Values{"targets": {"group-1"}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range seen {
		if e["id"] == ev["id"] {
			found = true
			if fmt.Sprint(e["targets"]) != "[group-1]" {
				t.Fatalf("the VEN sees targets it was not granted: %v", e["targets"])
			}
		}
	}
	if !found {
		t.Fatal("the VEN does not see its event")
	}
	do(ven, http.MethodPost, "/reports", oadr3.Object{"eventID": ev["id"], "clientName": "site-1", "resources": []any{map[string]any{
		"resourceName": "meter-1", "intervals": []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "USAGE", "values": []any{2.5}}}}}}}}, 201)
	do(bl, http.MethodGet, "/programs/nope", nil, 404)
	do(bl, http.MethodDelete, "/events/"+oadr3.Str(ev, "id"), nil, 200)
	var notifiers map[string]any
	if _, err := ven.Do(ctx, http.MethodGet, "/notifiers", nil, nil, &notifiers); err != nil {
		t.Fatal(err)
	}

	notes := h.wait(t, 3)
	for _, n := range notes {
		_ = val.Schema("notification", n)
	}
	var first map[string]any
	_ = json.Unmarshal(notes[0], &first)
	if first["objectType"] != "PROGRAM" || first["operation"] != "CREATE" {
		t.Fatalf("first notification: %s", notes[0])
	}
	h.mu.Lock()
	if h.auth[0] != "Bearer hook-token" {
		t.Fatalf("callback authorisation %q", h.auth[0])
	}
	h.mu.Unlock()
	checkSpec(t, val, true)
}

// The same against the OpenADR 3.0.1 definition, with the VTN in 3.0
// mode.
func TestOurClientAgainstOurVTN30(t *testing.T) {
	needSpec(t)
	val := newSpecValidator(t, "3.0.1")
	v, err := vtn.New(vtn.Config{Version: vtn.Version30,
		Clients:   []vtn.Client{{ClientID: "bl", Secret: "bl-secret", Role: vtn.RoleBL}, {ClientID: "ven", Secret: "ven-secret", Role: vtn.RoleVEN}},
		Validator: val})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	base := fmt.Sprintf("http://127.0.0.1:%d", listenVTN(t, v))
	v.SetPublicURL(base)
	ctx := context.Background()
	// 3.0 has no token endpoint discovery: the token URL is configured.
	bl := oadr3.NewClient(oadr3.ClientConfig{BaseURL: base, ClientID: "bl", Secret: "bl-secret", Validator: val, TokenURL: base + "/auth/token"})
	ven := oadr3.NewClient(oadr3.ClientConfig{BaseURL: base, ClientID: "ven", Secret: "ven-secret", Validator: val, TokenURL: base + "/auth/token"})
	g := []any{map[string]any{"type": "GROUP", "values": []any{"g1"}}}
	var p, x oadr3.Object
	if _, err := bl.Do(ctx, http.MethodPost, "/programs", nil, oadr3.Object{"programName": "p", "targets": g}, &p); err != nil {
		t.Fatal(err)
	}
	if _, err := ven.Do(ctx, http.MethodPost, "/vens", nil, oadr3.Object{"venName": "v1"}, &x); err != nil {
		t.Fatal(err)
	}
	if _, err := bl.Do(ctx, http.MethodPut, "/vens/"+oadr3.Str(x, "id"), nil, oadr3.Object{"venName": "v1", "targets": g}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := bl.Do(ctx, http.MethodPost, "/events", nil, oadr3.Object{"programID": p["id"], "eventName": "e", "targets": g,
		"intervals": []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "PRICE", "values": []any{1}}}}}}, nil); err != nil {
		t.Fatal(err)
	}
	evs, err := ven.All(ctx, "/events", url.Values{"targetType": {"GROUP"}, "targetValues": {"g1"}})
	if err != nil || len(evs) != 1 {
		t.Fatalf("3.0 events: %v %v", evs, err)
	}
	checkSpec(t, val, true)
}

// swapVTN serves the current VTN; each peer test gets a fresh one on the
// same address.
type swapVTN struct{ cur atomic.Pointer[vtn.VTN] }

func (s *swapVTN) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.cur.Load().ServeHTTP(w, r) }

// openleadr-rs's client integration tests (openleadr-client/tests at
// v0.2.6) against our VTN. They take the VTN from OPENADR_VTN_URL and
// OPENLEADR_RS_VTN_URL and log in as admin/admin; each expects an empty
// VTN, so every test runs alone against a fresh one. Both ends are
// checked against the OpenADR 3.1.0 definition.
func TestOpenLEADRRSClientSuiteAgainstOurVTN(t *testing.T) {
	needDocker(t)
	val := newSpecValidator(t, "3.1.0")
	build(t, imageOpenLEADRRSClient, "openleadr-rs-client")
	pgPort := freePort(t)
	pg := startPeer(t, "-p", fmt.Sprintf("0.0.0.0:%d:5432", pgPort),
		"-e", "POSTGRES_USER=openadr", "-e", "POSTGRES_PASSWORD=openadr", "-e", "POSTGRES_DB=openadr", imagePostgres)
	deadline := time.Now().Add(60 * time.Second)
	for exec.Command("docker", "exec", pg.name, "pg_isready", "-U", "openadr", "-h", "127.0.0.1").Run() != nil {
		if time.Now().After(deadline) {
			t.Fatalf("PostgreSQL did not start:\n%s", pg.output())
		}
		time.Sleep(500 * time.Millisecond)
	}
	sw := &swapVTN{}
	fresh := func() {
		// event/delete expects openleadr-rs's order of events (the
		// definition leaves the order to the VTN).
		v, err := vtn.New(vtn.Config{Clients: []vtn.Client{{ClientID: "admin", Secret: "admin", Role: vtn.RoleBL}}, Validator: val,
			EventOrder: vtn.EventsByPriority})
		if err != nil {
			t.Fatal(err)
		}
		if old := sw.cur.Swap(v); old != nil {
			_ = old.Close()
		}
	}
	fresh()
	port := listenVTN(t, sw)
	runner := startPeer(t, "--add-host=host.docker.internal:host-gateway", imageOpenLEADRRSClient)
	time.Sleep(time.Second)

	suite := []struct{ file, test string }{
		{"basic-read", "basic_create_read"},
		{"program", "get"}, {"program", "delete"}, {"program", "update"}, {"program", "update_same_name"},
		{"program", "create_same_name"}, {"program", "retrieve_all_with_filter"},
		{"event", "get"}, {"event", "delete"}, {"event", "update"}, {"event", "update_same_name"},
		{"event", "create_same_name"}, {"event", "retrieve_all_with_filter"}, {"event", "get_program_events"},
		{"event", "filter_constraint_violation"},
		{"ven", "ven_crud"}, {"ven", "resource_crud"},
	}
	// divergent are tests that check openleadr-rs's own choices where the
	// definition says otherwise; they must fail at the named line.
	divergent := map[string]string{
		"event/filter_constraint_violation": "event.rs:335", // limit=0 refused; the 3.1.0 definition allows limit 0 (minimum: 0)
	}
	vtnURL := fmt.Sprintf("http://host.docker.internal:%d/", port)
	passed := 0
	for _, s := range suite {
		t.Run(s.file+"/"+s.test, func(t *testing.T) {
			if where, ok := divergent[s.file+"/"+s.test]; ok {
				fresh()
				out, _ := exec.Command("docker", "exec",
					"-e", "OPENADR_VTN_URL="+vtnURL, "-e", "OPENLEADR_RS_VTN_URL="+vtnURL,
					"-e", fmt.Sprintf("DATABASE_URL=postgres://openadr:openadr@host.docker.internal:%d/openadr", pgPort),
					runner.name, "cargo", "test", "-q", "-p", "openleadr-client", "--test", s.file, "--", "--exact", s.test, "--test-threads=1").CombinedOutput()
				if !strings.Contains(string(out), where) {
					t.Fatalf("expected the divergent test to stop at %s:\n%s", where, out)
				}
				t.Logf("diverges by design at %s", where)
				return
			}
			fresh()
			out, err := exec.Command("docker", "exec",
				"-e", "OPENADR_VTN_URL="+vtnURL, "-e", "OPENLEADR_RS_VTN_URL="+vtnURL,
				"-e", fmt.Sprintf("DATABASE_URL=postgres://openadr:openadr@host.docker.internal:%d/openadr", pgPort),
				runner.name, "cargo", "test", "-q", "-p", "openleadr-client", "--test", s.file, "--", "--exact", s.test, "--test-threads=1").CombinedOutput()
			if err != nil || !strings.Contains(string(out), "1 passed") {
				t.Fatalf("openleadr-rs test %s/%s: %v\n%s", s.file, s.test, err, out)
			}
			passed++
		})
	}
	t.Logf("openleadr-rs client tests passed against our VTN: %d of %d", passed, len(suite))
	checkSpec(t, val, false)
}
