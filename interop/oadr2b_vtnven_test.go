// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr/internal/testpki"
	"github.com/cB-Sigma/openadr/oadr2b"
	"github.com/cB-Sigma/openadr/oadr2b/ven"
	"github.com/cB-Sigma/openadr/oadr2b/vtn"
)

// vvEventually polls cond until it holds or within passes.
func vvEventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, within)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// OpenLEADR 0.5.36's VEN client (OpenADRClient) against oadr2b/vtn, over
// plain HTTP and over mutual TLS with XML signatures both ways:
// registration, report registration with requests, oadrCreatedReport and
// periodic oadrUpdateReport, the VTN's METADATA (oadrRegisterReport), an
// event by poll with oadrCreatedEvent (optIn), a modified and a cancelled
// event, oadrCreateOpt and oadrCancelOpt, oadrCancelReport from the VTN,
// oadrRequestReregistration, and cancellation of the registration by the
// VEN. OpenLEADR validates every message it receives against the 2.0b
// schema.
func TestOpenLEADRVENWithOurVTN(t *testing.T) {
	needDocker(t)
	build(t, imageOpenLEADR, "openleadr")
	for _, secure := range []bool{false, true} {
		name := "http"
		if secure {
			name = "tls-signed"
		}
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			var regs []vtn.RegistrationInfo
			var values []float64
			opts := map[string]string{}
			cancelled := false
			cfg := vtn.Config{VtnID: "SIGMA-VTN", PollFreq: time.Second, SendMetadata: true,
				OnCreatePartyRegistration: func(_ context.Context, info vtn.RegistrationInfo) (string, string, error) {
					mu.Lock()
					regs = append(regs, info)
					mu.Unlock()
					return "ven-olr", "", nil
				},
				OnCancelPartyRegistration: func(context.Context, vtn.Registration) {
					mu.Lock()
					cancelled = true
					mu.Unlock()
				},
				OnRegisterReport: func(_ context.Context, _ string, reports []oadr2b.Report) []oadr2b.ReportRequest {
					return vtn.RequestAll(reports, time.Second, 2*time.Second)
				},
				OnUpdateReport: func(_ context.Context, _ string, reports []oadr2b.Report) error {
					mu.Lock()
					defer mu.Unlock()
					for _, r := range reports {
						if r.Intervals == nil {
							continue
						}
						for _, iv := range r.Intervals.Interval {
							for _, p := range iv.ReportPayload {
								if p.PayloadFloat != nil {
									values = append(values, p.PayloadFloat.Value)
								}
							}
						}
					}
					return nil
				},
				OnEventResponse: func(_ context.Context, _, eventID, optType string) {
					mu.Lock()
					opts[eventID] = optType
					mu.Unlock()
				}}
			args := []string{"--add-host=host.docker.internal:host-gateway"}
			var script []string
			var tc *tls.Config
			if secure {
				pki := testpki.New(t)
				vtnLeaf := pki.Issue(t, "host.docker.internal", "host.docker.internal", "127.0.0.1")
				venLeaf := pki.Issue(t, "olr-ven")
				dir := t.TempDir()
				pki.Write(t, dir, map[string]testpki.Leaf{"ven": venLeaf})
				args = append(args, "-v", dir+":/certs:ro")
				s, _ := oadr2b.NewSigner(vtnLeaf.TLS)
				script = []string{"/certs", s.Fingerprint()}
				cfg.Signer, cfg.RequireSignatures = s, true
				var err error
				if tc, err = vtn.ServerTLSConfig(oadr2b.TLSProfileCompatible, pki.Pool, vtnLeaf.TLS); err != nil {
					t.Fatal(err)
				}
			}
			v := vtn.New(cfg)
			defer v.Close()
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			served := make(chan error, 1)
			go func() { served <- v.Serve(ctx, ln, tc) }()
			defer func() { cancel(); <-served }()
			scheme := "http"
			if secure {
				scheme = "https"
			}
			url := fmt.Sprintf("%s://host.docker.internal:%d/OpenADR2/Simple/2.0b", scheme, ln.Addr().(*net.TCPAddr).Port)
			p := startPeer(t, append(append(args, imageOpenLEADR, "python", "-u", "olr_ven.py", url), script...)...)

			p.expect(60*time.Second, "registered ven-olr")
			mu.Lock()
			// OpenLEADR 0.5.36 sends oadrXmlSignature false even when it
			// signs, so that flag is not checked.
			if len(regs) != 1 || regs[0].VenName != "olr-ven" || !regs[0].HTTPPullModel {
				t.Errorf("registration info %+v", regs)
			}
			mu.Unlock()
			if m := v.Metadata("ven-olr"); len(m) != 1 || m[0].ReportSpecifierID != "olr-usage" || m[0].Descriptions[0].RID != "olr-voltage" {
				t.Fatalf("OpenLEADR's METADATA: %+v", m)
			}
			vvEventually(t, 20*time.Second, "oadrUpdateReport with 231.5", func() bool {
				mu.Lock()
				defer mu.Unlock()
				for _, x := range values {
					if x == 231.5 {
						return true
					}
				}
				return false
			})

			if err := v.AddEvent("ven-olr", vtn.EventSpec{ID: "ev-1", MarketContext: "http://sigma.test/mc", Start: time.Now(),
				Intervals: []vtn.IntervalSpec{{Duration: 30 * time.Minute, Value: 2}}}.Build()); err != nil {
				t.Fatal(err)
			}
			p.expect(20*time.Second, "event ev-1 0 active SIMPLE 2.0")
			vvEventually(t, 10*time.Second, "optIn for ev-1", func() bool { return v.OptState("ven-olr", "ev-1") == "optIn" })

			ev := vtn.EventSpec{ID: "ev-1", MarketContext: "http://sigma.test/mc", Start: time.Now(),
				Intervals: []vtn.IntervalSpec{{Duration: 30 * time.Minute, Value: 3}}}.Build()
			if err := v.ModifyEvent("ven-olr", ev); err != nil {
				t.Fatal(err)
			}
			p.expect(20*time.Second, "event ev-1 1 active SIMPLE 3.0")
			if err := v.CancelEvent("ven-olr", "ev-1"); err != nil {
				t.Fatal(err)
			}
			p.expect(20*time.Second, "event ev-1 2 cancelled SIMPLE")
			// Once OpenLEADR acknowledged the cancellation the VTN stops
			// sending the event.
			vvEventually(t, 20*time.Second, "cancellation acknowledged", func() bool {
				return len(v.Events("ven-olr")) == 0
			})

			// oadrCreateOpt and oadrCancelOpt for a new event.
			if err := v.AddEvent("ven-olr", vtn.EventSpec{ID: "ev-2", MarketContext: "http://sigma.test/mc", Start: time.Now(),
				Intervals: []vtn.IntervalSpec{{Duration: 30 * time.Minute, Value: 1}}}.Build()); err != nil {
				t.Fatal(err)
			}
			p.expect(20*time.Second, "event ev-2 0 active SIMPLE 1.0")
			vvEventually(t, 10*time.Second, "optIn for ev-2", func() bool { return v.OptState("ven-olr", "ev-2") == "optIn" })
			p.send("opt ev-2 0 optOut")
			line := p.expect(20*time.Second, "opt-created")
			if v.OptState("ven-olr", "ev-2") != "optOut" {
				t.Fatalf("opt state after oadrCreateOpt: %q (%s)", v.OptState("ven-olr", "ev-2"), line)
			}
			p.send("cancelopt " + strings.TrimPrefix(line, "opt-created "))
			p.expect(20*time.Second, "opt-cancelled", "True")

			// The VTN cancels the report request; OpenLEADR drops it.
			var ids []string
			for id := range v.ReportRequests("ven-olr") {
				ids = append(ids, id)
			}
			if len(ids) != 1 {
				t.Fatalf("report requests %v", ids)
			}
			if err := v.CancelReport("ven-olr", ids, false); err != nil {
				t.Fatal(err)
			}
			p.expect(20*time.Second, "received oadrCancelReport")
			vvEventually(t, 20*time.Second, "report request gone at OpenLEADR", func() bool {
				p.send("state")
				l := p.expect(5*time.Second, "state ven-olr")
				return strings.HasSuffix(l, " -")
			})

			// The VTN asks for a re-registration; the IDs stay.
			reg, _ := v.Registration(context.Background(), "ven-olr")
			if err := v.Reregister("ven-olr"); err != nil {
				t.Fatal(err)
			}
			p.expect(20*time.Second, "received oadrRequestReregistration")
			p.expect(20*time.Second, "received oadrCreatedPartyRegistration")
			if r, _ := v.Registration(context.Background(), "ven-olr"); r == nil || r.RegistrationID != reg.RegistrationID {
				t.Fatalf("after re-registration: %+v", r)
			}

			p.send("cancel")
			p.expect(20*time.Second, "canceled")
			mu.Lock()
			defer mu.Unlock()
			if !cancelled {
				t.Fatal("the VTN was not told of the cancellation")
			}
			if r, _ := v.Registration(context.Background(), "ven-olr"); r != nil {
				t.Fatalf("still registered: %+v", r)
			}
			if opts["ev-1"] == "" {
				t.Fatalf("opts %v", opts)
			}
		})
	}
}

// OpenLEADR 0.5.36's VTN (OpenADRServer) against oadr2b/ven, over plain
// HTTP and over mutual TLS with XML signatures both ways: registration
// with the VTN's poll frequency, report registration and OpenLEADR's
// report requests, periodic oadrUpdateReport from ReadData, events by
// oadrRequestEvent and by poll with oadrCreatedEvent (optIn from
// OnEvent), and cancellation of the registration by the VEN.
func TestOurVENWithOpenLEADRVTN(t *testing.T) {
	needDocker(t)
	build(t, imageOpenLEADR, "openleadr")
	for _, secure := range []bool{false, true} {
		name := "http"
		if secure {
			name = "tls-signed"
		}
		t.Run(name, func(t *testing.T) {
			port := freePort(t)
			var mu sync.Mutex
			seen := map[string]float64{}
			vc := ven.Config{VTNURL: fmt.Sprintf("http://127.0.0.1:%d/OpenADR2/Simple/2.0b", port), VenName: "sigma-ven",
				Reports: []oadr2b.Report{{ReportSpecifierID: "usage-1", ReportName: "METADATA_TELEMETRY_USAGE", Duration: &oadr2b.DurationProp{Duration: "PT1H"},
					Descriptions: []oadr2b.ReportDescription{{RID: "power", ReportDataSource: &oadr2b.Target{ResourceID: []string{"resource-1"}},
						ReportType: "usage", ReadingType: "Direct Read", SamplingRate: &oadr2b.SamplingRate{MinPeriod: "PT1S", MaxPeriod: "PT1H"},
						ItemBase: &oadr2b.ItemBase{XMLName: oadr2b.XMLName(oadr2b.NSPower, "powerReal"), ItemDescription: "RealPower", ItemUnits: "W", SiScaleCode: "none"}}}}},
				OnEvent: func(_ context.Context, ev oadr2b.OadrEvent) string {
					mu.Lock()
					seen[ev.EiEvent.Descriptor.EventID] = ev.EiEvent.Signals.Signal[0].Intervals.Interval[0].SignalPayload.PayloadFloat.Value
					mu.Unlock()
					return "optIn"
				},
				ReadData: func(context.Context, string, string, time.Time) (oadr2b.ReportPayload, bool) {
					return oadr2b.ReportPayload{PayloadFloat: &oadr2b.PayloadFloat{Value: 640}}, true
				}}
			args := []string{"-p", fmt.Sprintf("127.0.0.1:%d:%d", port, port)}
			script := []string{"python", "-u", "olr_vtn.py", strconv.Itoa(port), "ven-olr"}
			if secure {
				pki := testpki.New(t)
				vtnLeaf := pki.Issue(t, "olr-vtn", "127.0.0.1", "localhost")
				venLeaf := pki.Issue(t, "sigma-ven", "127.0.0.1", "localhost")
				dir := t.TempDir()
				pki.Write(t, dir, map[string]testpki.Leaf{"vtn": vtnLeaf})
				args = append(args, "-v", dir+":/certs:ro")
				s, _ := oadr2b.NewSigner(venLeaf.TLS)
				script = append(script, "/certs", s.Fingerprint())
				vc.VTNURL = fmt.Sprintf("https://127.0.0.1:%d/OpenADR2/Simple/2.0b", port)
				vc.Certificate, vc.RootCAs, vc.Signer, vc.RequireSignatures = &venLeaf.TLS, pki.Pool, s, true
				vc.VTNFingerprint = oadr2b.Fingerprint(vtnLeaf.TLS.Certificate[0])
			}
			p := startPeer(t, append(append(args, imageOpenLEADR), script...)...)
			p.expect(60*time.Second, "ready")
			waitPort(t, port, 10*time.Second)

			vn, err := ven.New(vc)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- vn.Run(ctx) }()
			signed := "False"
			if secure {
				signed = "True"
			}
			p.expect(20*time.Second, "registration sigma-ven True "+signed)
			vvEventually(t, 10*time.Second, "registration", func() bool { return vn.RegistrationID() == "reg-olr-1" })
			if vn.VenID() != "ven-olr" || vn.PollEvery() != time.Second {
				t.Fatalf("venID %q, polling every %s", vn.VenID(), vn.PollEvery())
			}
			p.expect(10*time.Second, "register-report", "resource-1")
			p.expect(20*time.Second, "report resource-1 RealPower 640")

			p.send("event olr-ev-1 2")
			p.expect(10*time.Second, "event-added olr-ev-1")
			p.expect(20*time.Second, "opt ven-olr olr-ev-1 optIn")
			p.send("event olr-ev-2 3")
			p.expect(20*time.Second, "opt ven-olr olr-ev-2 optIn")
			mu.Lock()
			if seen["olr-ev-1"] != 2 || seen["olr-ev-2"] != 3 {
				t.Errorf("events seen %v", seen)
			}
			mu.Unlock()
			if vn.Opt("olr-ev-2") != "optIn" {
				t.Errorf("VEN opt %q", vn.Opt("olr-ev-2"))
			}

			if err := vn.CancelRegistration(ctx); err != nil {
				t.Fatalf("cancel: %v", err)
			}
			p.expect(10*time.Second, "cancel ven-olr reg-olr-1")
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
