// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr/oadr3"
)

// Client credentials of openleadr-rs's own user fixtures
// (fixtures/users.sql in its repository, loaded at test time).
const (
	rsBLClient, rsBLSecret   = "bl-client", "bl-client"
	rsVENClient, rsVENSecret = "ven-client-client-id", "ven-client"
)

// startOpenLEADRRS runs PostgreSQL and the openleadr-rs VTN (built from
// peer/openleadr-rs at a pinned commit), loads openleadr-rs's user
// fixtures and returns the VTN's base URL.
func startOpenLEADRRS(t *testing.T) string {
	t.Helper()
	build(t, imageOpenLEADRRS, "openleadr-rs")
	pgPort, vtnPort := freePort(t), freePort(t)
	pg := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:5432", pgPort),
		"-e", "POSTGRES_USER=openadr", "-e", "POSTGRES_PASSWORD=openadr", "-e", "POSTGRES_DB=openadr", imagePostgres)
	deadline := time.Now().Add(60 * time.Second)
	for exec.Command("docker", "exec", pg.name, "pg_isready", "-U", "openadr", "-h", "127.0.0.1").Run() != nil {
		if time.Now().After(deadline) {
			t.Fatalf("PostgreSQL did not start:\n%s", pg.output())
		}
		time.Sleep(500 * time.Millisecond)
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", vtnPort)
	vtn := startPeer(t, "--add-host=host.docker.internal:host-gateway", "-p", fmt.Sprintf("127.0.0.1:%d:3000", vtnPort),
		"-e", fmt.Sprintf("DATABASE_URL=postgres://openadr:openadr@host.docker.internal:%d/openadr", pgPort),
		"-e", "OAUTH_TOKEN_URL="+base+"/auth/token", "-e", "RUST_LOG=openleadr_vtn=info", imageOpenLEADRRS)
	deadline = time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(base + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("openleadr-rs did not start:\n%s", vtn.output())
		}
		time.Sleep(500 * time.Millisecond)
	}
	sql, err := exec.Command("docker", "run", "--rm", "--entrypoint", "cat", imageOpenLEADRRS, "/fixtures/users.sql").Output()
	if err != nil {
		t.Fatalf("reading the user fixtures: %v", err)
	}
	load := exec.Command("docker", "exec", "-i", pg.name, "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "openadr", "-d", "openadr")
	load.Stdin = bytes.NewReader(sql)
	if out, err := load.CombinedOutput(); err != nil {
		t.Fatalf("loading the user fixtures: %v\n%s", err, out)
	}
	return base
}

// The OpenADR 3 client against openleadr-rs's VTN: token endpoint
// discovery and the client-credentials grant, creating objects, paging
// through more objects than one page holds, event windows of the VTN's
// events, the VTN's error answers as HTTPError, and wrong credentials.
func TestAPIClientWithOpenLEADRRS(t *testing.T) {
	needDocker(t)
	base := startOpenLEADRRS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	bl := oadr3.NewClient(oadr3.ClientConfig{BaseURL: base, ClientID: rsBLClient, Secret: rsBLSecret})
	tok, err := bl.Token(ctx)
	if err != nil || tok == "" {
		t.Fatalf("token: %q, %v", tok, err)
	}
	var progID string
	n := oadr3.MaxLimit + 3
	for i := range n {
		var prog oadr3.Object
		if _, err := bl.Do(ctx, http.MethodPost, "/programs", nil, oadr3.Object{"programName": fmt.Sprintf("p-%03d", i)}, &prog); err != nil {
			t.Fatalf("create program %d: %v", i, err)
		}
		if prog["objectType"] != oadr3.TypeProgram || oadr3.Str(prog, "id") == "" {
			t.Fatalf("program: %v", prog)
		}
		progID = oadr3.Str(prog, "id")
	}
	all, err := bl.All(ctx, "/programs", nil)
	if err != nil {
		t.Fatalf("all programs: %v", err)
	}
	if len(all) != n {
		t.Fatalf("paged through %d programs, created %d", len(all), n)
	}
	start := time.Now().UTC().Truncate(time.Second)
	var ev oadr3.Object
	if _, err := bl.Do(ctx, http.MethodPost, "/events", nil, oadr3.Object{
		"programID": progID, "eventName": "e-1",
		"intervalPeriod": map[string]any{"start": start.Format(time.RFC3339), "duration": "PT2H"},
		"intervals":      []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "PRICE", "values": []any{0.25}}}}},
	}, &ev); err != nil {
		t.Fatalf("create event: %v", err)
	}
	evs, err := bl.All(ctx, "/events", url.Values{"programID": {progID}})
	if err != nil || len(evs) != 1 {
		t.Fatalf("events of the program: %v, %v", evs, err)
	}
	if w := oadr3.EventWindow(evs[0]); !w.Start.Equal(start) || !w.End.Equal(start.Add(2*time.Hour)) {
		t.Fatalf("event window: %+v (start %s)", w, start)
	}

	// The VTN's error answers come back as HTTPError.
	_, err = bl.Do(ctx, http.MethodGet, "/programs/no-such-program", nil, nil, nil)
	var he *oadr3.HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusNotFound {
		t.Fatalf("missing program: %v", err)
	}
	// A VEN client may not create programs.
	ven := oadr3.NewClient(oadr3.ClientConfig{BaseURL: base, ClientID: rsVENClient, Secret: rsVENSecret})
	_, err = ven.Do(ctx, http.MethodPost, "/programs", nil, oadr3.Object{"programName": "not-allowed"}, nil)
	if !errors.As(err, &he) || he.Status != http.StatusForbidden {
		t.Fatalf("program created by a VEN client: %v", err)
	}
	// Wrong credentials stop at the token endpoint.
	bad := oadr3.NewClient(oadr3.ClientConfig{BaseURL: base, ClientID: rsBLClient, Secret: "wrong"})
	if _, err := bad.Token(ctx); err == nil {
		t.Fatal("a token for a wrong secret")
	}
}
