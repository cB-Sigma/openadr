// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package mdns

import (
	"context"
	"maps"
	"math/rand/v2"
	"net"
	"testing"
	"time"

	mdnslib "github.com/cB-Sigma/mdns"
)

func TestVTNRecords(t *testing.T) {
	got := VTNRecords("3.1.0", "/openadr3/3.1.0/", "myvtn.local.", 883, []string{"a", "b"}, false, "")
	want := map[string]string{
		"version":       "3.1.0",
		"base_path":     "openadr3/3.1.0",
		"local_url":     "https://myvtn.local:883/openadr3/3.1.0",
		"program_names": "a,b",
		"requires_auth": "False",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	got = VTNRecords("3.1.0", "", "myvtn", 443, nil, true, "https://x/openapi.yaml")
	if got["requires_auth"] != "True" || got["local_url"] != "https://myvtn.local:443" || got["openapi_url"] != "https://x/openapi.yaml" || got["program_names"] != "" {
		t.Fatalf("got %v", got)
	}
}

// TestVTNAnnounceBrowse announces a VTN with its TXT records on a real
// interface (on a non-standard port, so the OS responder on 5353 is
// untouched), browses for it as a VEN would, renames a second VTN that
// claims the same instance name, and checks the goodbye on Close.
//
// Covers: SIG-IPE-2364, SIG-IPE-2365
func TestVTNAnnounceBrowse(t *testing.T) {
	if testing.Short() {
		t.Skip("uses the network; skipped with -short")
	}
	port := 20000 + rand.IntN(30000)
	ifi, err := mdnslib.TestInterface(port)
	if err != nil {
		t.Skipf("%v", err)
	}
	opts := Options{Interfaces: []net.Interface{*ifi}, Port: port, Loopback: true, Wait: 2 * time.Second}
	svc := Service{Instance: "Site gateway", Host: "vtn-test.local", Port: 8443,
		TXT: VTNRecords("3.1.0", "/openadr3/3.1.0", "vtn-test", 8443, []string{"local", "flex"}, true, "https://vtn-test.local:8443/openadr3/3.1.0/openapi.yaml")}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a, err := Announce(ctx, svc, opts)
	if err != nil {
		t.Fatalf("Announce on %s port %d: %v", ifi.Name, port, err)
	}
	defer a.Close()

	got, err := Browse(ctx, ServiceType, opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("found %+v", got)
	}
	s := got[0]
	if s.Instance != svc.Instance || s.Host != "vtn-test.local" || s.Port != 8443 || !maps.Equal(s.TXT, svc.TXT) || len(s.IPs) == 0 {
		t.Fatalf("found %+v", s)
	}
	if s.Addr() != "vtn-test.local:8443" {
		t.Errorf("Addr %q does not favour the .local host", s.Addr())
	}

	// A second VTN with the same instance name is renamed, not refused.
	dup := svc
	dup.Port = 9443
	b, err := Announce(ctx, dup, opts)
	if err != nil {
		t.Fatalf("second VTN: %v", err)
	}
	got, _ = Browse(ctx, ServiceType, opts)
	names := map[string]int{}
	for _, x := range got {
		names[x.Instance] = x.Port
	}
	if names["Site gateway"] != 8443 || names["Site gateway (2)"] != 9443 {
		t.Errorf("after the second VTN: %+v", got)
	}
	_ = b.Close()

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	got, err = Browse(ctx, ServiceType, Options{Interfaces: opts.Interfaces, Port: port, Loopback: true, Wait: 1500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("after goodbye: %+v", got)
	}
}
