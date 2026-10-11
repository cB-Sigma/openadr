// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ven_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr/internal/testpki"
	"github.com/cB-Sigma/openadr/oadr2b"
	"github.com/cB-Sigma/openadr/oadr2b/ven"
	"github.com/cB-Sigma/openadr/oadr2b/vtn"
)

func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func metadata() []oadr2b.Report {
	rate := &oadr2b.SamplingRate{MinPeriod: "PT1S", MaxPeriod: "PT1H"}
	src := &oadr2b.Target{ResourceID: []string{"meter-1"}}
	return []oadr2b.Report{{ReportSpecifierID: "usage", ReportName: "METADATA_TELEMETRY_USAGE", Duration: &oadr2b.DurationProp{Duration: "PT1H"},
		Descriptions: []oadr2b.ReportDescription{
			{RID: "power", ReportDataSource: src, ReportType: "usage", ReadingType: "Direct Read", SamplingRate: rate,
				ItemBase: &oadr2b.ItemBase{XMLName: oadr2b.XMLName(oadr2b.NSPower, "powerReal"), ItemDescription: "RealPower", ItemUnits: "W"}},
			{RID: "energy", ReportDataSource: src, ReportType: "usage", ReadingType: "Direct Read", SamplingRate: rate,
				ItemBase: &oadr2b.ItemBase{XMLName: oadr2b.XMLName(oadr2b.NSPower, "energyReal"), ItemDescription: "RealEnergy", ItemUnits: "Wh", SiScaleCode: "k"}},
		}}}
}

// recorder collects what the VTN's callbacks see.
type recorder struct {
	mu      sync.Mutex
	values  map[string]float64 // rID → last value
	answers map[string]string  // eventID → optType
	created int
}

func (r *recorder) vtnConfig(cfg vtn.Config) vtn.Config {
	r.values, r.answers = map[string]float64{}, map[string]string{}
	cfg.OnRegisterReport = func(_ context.Context, _ string, reports []oadr2b.Report) []oadr2b.ReportRequest {
		return vtn.RequestAll(reports, time.Second, time.Second)
	}
	cfg.OnUpdateReport = func(_ context.Context, _ string, reports []oadr2b.Report) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, rep := range reports {
			for _, iv := range rep.Intervals.Interval {
				for _, p := range iv.ReportPayload {
					if p.PayloadFloat != nil {
						r.values[p.RID] = p.PayloadFloat.Value
					}
				}
			}
		}
		return nil
	}
	cfg.OnEventResponse = func(_ context.Context, _, eventID, optType string) {
		r.mu.Lock()
		r.answers[eventID] = optType
		r.mu.Unlock()
	}
	cfg.OnCreatedReport = func(context.Context, string, []string) {
		r.mu.Lock()
		r.created++
		r.mu.Unlock()
	}
	return cfg
}

func (r *recorder) value(rid string) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.values[rid]
}

func (r *recorder) answer(eventID string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.answers[eventID]
}

func event(id string, level float64) oadr2b.OadrEvent {
	return vtn.EventSpec{ID: id, MarketContext: "http://mc.test", Start: time.Now().Add(-time.Minute),
		Intervals: []vtn.IntervalSpec{{Duration: time.Hour, Value: level}}}.Build()
}

// venConfig is a VEN that opts out of events named "no-…" and reads
// power 640 W and energy 1.5 kWh.
func venConfig(url string, seen *sync.Map) ven.Config {
	return ven.Config{VTNURL: url, VenName: "test-ven", PollFreq: 50 * time.Millisecond, Reports: metadata(),
		OnEvent: func(_ context.Context, ev oadr2b.OadrEvent) string {
			d := ev.EiEvent.Descriptor
			if seen != nil {
				n, _ := seen.LoadOrStore(d.EventID, new(int))
				*(n.(*int))++
			}
			if len(d.EventID) > 3 && d.EventID[:3] == "no-" {
				return "optOut"
			}
			return "optIn"
		},
		ReadData: func(_ context.Context, _, rid string, _ time.Time) (oadr2b.ReportPayload, bool) {
			v := map[string]float64{"power": 640, "energy": 1.5}[rid]
			return oadr2b.ReportPayload{PayloadFloat: &oadr2b.PayloadFloat{Value: v}}, true
		}}
}

// flow runs the whole exchange between a VTN and a running VEN.
func flow(t *testing.T, v *vtn.VTN, rec *recorder, vn *ven.VEN, seen *sync.Map) {
	t.Helper()
	ctx := context.Background()
	eventually(t, 5*time.Second, "registration", func() bool { return vn.RegistrationID() != "" })
	venID := vn.VenID()
	eventually(t, 5*time.Second, "report data", func() bool { return rec.value("power") == 640 && rec.value("energy") == 1.5 })

	if err := v.AddEvent(venID, event("ev-1", 2)); err != nil {
		t.Fatal(err)
	}
	if err := v.AddEvent(venID, event("no-2", 1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "opt answers", func() bool { return rec.answer("ev-1") == "optIn" && rec.answer("no-2") == "optOut" })
	if vn.Opt("ev-1") != "optIn" || len(vn.Events()) != 2 {
		t.Fatalf("VEN events %+v", vn.Events())
	}
	// A modification asks OnEvent again; an unchanged event does not.
	ev := event("ev-1", 3)
	if err := v.ModifyEvent(venID, ev); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "modified event", func() bool {
		evs := vn.Events()
		return len(evs) == 2 && evs[0].EiEvent.Descriptor.ModificationNumber == 1
	})
	if n, _ := seen.Load("ev-1"); *(n.(*int)) != 2 {
		t.Fatalf("OnEvent for ev-1 called %d times", *(n.(*int)))
	}
	if n, _ := seen.Load("no-2"); *(n.(*int)) != 1 {
		t.Fatalf("OnEvent for no-2 called %d times", *(n.(*int)))
	}
	// An opt changes the VTN's view.
	if _, err := vn.OptEvent(ctx, "ev-1", "optOut", "x-schedule"); err != nil {
		t.Fatal(err)
	}
	if v.OptState(venID, "ev-1") != "optOut" {
		t.Fatalf("after oadrCreateOpt: %q", v.OptState(venID, "ev-1"))
	}
	if err := v.CancelEvent(venID, "no-2"); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "cancelled event acknowledged", func() bool {
		evs := v.Events(venID)
		return len(evs) == 1 && evs[0].EiEvent.Descriptor.EventID == "ev-1"
	})

	// The VTN cancels the report request.
	reqs := v.ReportRequests(venID)
	if len(reqs) != 1 {
		t.Fatalf("report requests %v", reqs)
	}
	var ids []string
	for id := range reqs {
		ids = append(ids, id)
	}
	if err := v.CancelReport(venID, ids, false); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "report cancelled at the VEN", func() bool { return len(vn.ReportRequests()) == 0 })

	// Re-registration keeps the registrationID.
	regID := vn.RegistrationID()
	if err := v.Reregister(venID); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "re-registration", func() bool { return len(v.ReportRequests(venID)) == 1 })
	if vn.RegistrationID() != regID {
		t.Fatalf("registrationID %q after re-registration, was %q", vn.RegistrationID(), regID)
	}
	// The VTN ends the registration; the VEN registers again.
	if err := v.CancelRegistration(venID); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "registration again", func() bool {
		r, _ := v.Registration(ctx, venID)
		return r != nil && r.RegistrationID != regID && vn.RegistrationID() == r.RegistrationID
	})
	// The VEN cancels; Run returns.
	if err := vn.CancelRegistration(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := v.Registration(ctx, venID); r != nil {
		t.Fatalf("still registered: %+v", r)
	}
}

func TestVENWithVTNPull(t *testing.T) {
	rec := &recorder{}
	v := vtn.New(rec.vtnConfig(vtn.Config{VtnID: "vtn-1", PollFreq: 2 * time.Second}))
	srv := httptest.NewServer(v)
	defer srv.Close()
	defer v.Close()
	seen := &sync.Map{}
	vn, err := ven.New(venConfig(srv.URL, seen))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() { done <- vn.Run(context.Background()) }()
	flow(t, v, rec, vn, seen)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the VEN cancelled")
	}
}

func TestVENWithVTNPush(t *testing.T) {
	rec := &recorder{}
	v := vtn.New(rec.vtnConfig(vtn.Config{VtnID: "vtn-1", PushRetry: 50 * time.Millisecond}))
	srv := httptest.NewServer(v)
	defer srv.Close()
	defer v.Close()
	seen := &sync.Map{}
	cfg := venConfig(srv.URL, seen)
	cfg.PushListen = "127.0.0.1:0"
	vn, err := ven.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- vn.Run(ctx) }()
	eventually(t, 5*time.Second, "registration", func() bool { return vn.RegistrationID() != "" })
	reg, _ := v.Registration(ctx, vn.VenID())
	if !reg.Push || reg.TransportAddress != vn.PushURL() {
		t.Fatalf("registration %+v", reg)
	}
	flow(t, v, rec, vn, seen)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Mutual TLS with the OpenADR suites and XML signatures both ways,
// pulling and pushed.
func TestVENWithVTNMutualTLSSigned(t *testing.T) {
	for _, push := range []bool{false, true} {
		name := "pull"
		if push {
			name = "push"
		}
		t.Run(name, func(t *testing.T) {
			pki := testpki.New(t)
			vtnLeaf := pki.Issue(t, "vtn", "127.0.0.1")
			venLeaf := pki.Issue(t, "ven", "127.0.0.1")
			vtnSigner, _ := oadr2b.NewSigner(vtnLeaf.TLS)
			venSigner, _ := oadr2b.NewSigner(venLeaf.TLS)
			pushTLS := &tls.Config{RootCAs: pki.Pool, Certificates: []tls.Certificate{vtnLeaf.TLS}}
			if err := oadr2b.ApplyTLSProfile(pushTLS, oadr2b.TLSProfileOpenADR); err != nil {
				t.Fatal(err)
			}
			rec := &recorder{}
			var fps sync.Map
			cfg := rec.vtnConfig(vtn.Config{VtnID: "vtn-tls", Signer: vtnSigner, RequireSignatures: true, PushRetry: 50 * time.Millisecond,
				PushClient: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: pushTLS}},
				OnCreatePartyRegistration: func(_ context.Context, info vtn.RegistrationInfo) (string, string, error) {
					fps.Store("fp", info.Fingerprint)
					return "ven-by-cert", "", nil
				}})
			v := vtn.New(cfg)
			defer v.Close()
			tc, err := vtn.ServerTLSConfig(oadr2b.TLSProfileOpenADR, pki.Pool, vtnLeaf.TLS)
			if err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewUnstartedServer(v)
			srv.TLS = tc
			srv.StartTLS()
			defer srv.Close()
			seen := &sync.Map{}
			vc := venConfig(srv.URL, seen)
			vc.Certificate, vc.RootCAs, vc.TLSProfile, vc.Signer, vc.RequireSignatures = &venLeaf.TLS, pki.Pool, oadr2b.TLSProfileOpenADR, venSigner, true
			if push {
				vc.PushListen = "127.0.0.1:0"
			}
			vn, err := ven.New(vc)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error)
			go func() { done <- vn.Run(context.Background()) }()
			eventually(t, 5*time.Second, "registration", func() bool { return vn.RegistrationID() != "" })
			if fp, _ := fps.Load("fp"); fp != venSigner.Fingerprint() || vn.VenID() != "ven-by-cert" {
				t.Fatalf("fingerprint %v, venID %s", fp, vn.VenID())
			}
			flow(t, v, rec, vn, seen)
			<-done
		})
	}
}

func TestPollFrequencyFromVTN(t *testing.T) {
	for _, c := range []struct {
		vtn  time.Duration
		want time.Duration
	}{{3 * time.Second, 3 * time.Second}, {100 * time.Millisecond, time.Second}} {
		v := vtn.New(vtn.Config{PollFreq: c.vtn})
		srv := httptest.NewServer(v)
		vn, err := ven.New(ven.Config{VTNURL: srv.URL + "/OpenADR2/Simple/2.0b"})
		if err != nil {
			t.Fatal(err)
		}
		if err := vn.Register(context.Background()); err != nil {
			t.Fatal(err)
		}
		if vn.PollEvery() != c.want {
			t.Errorf("VTN %s: polling every %s, want %s", c.vtn, vn.PollEvery(), c.want)
		}
		srv.Close()
		v.Close()
	}
}

// A VEN whose VTN forgot it registers anew.
func TestVTNForgetsVEN(t *testing.T) {
	v := vtn.New(vtn.Config{})
	defer v.Close()
	var current atomic.Pointer[vtn.VTN]
	current.Store(v)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { current.Load().ServeHTTP(w, r) }))
	defer srv.Close()
	vn, _ := ven.New(ven.Config{VTNURL: srv.URL, PollFreq: 50 * time.Millisecond})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = vn.Run(ctx) }()
	eventually(t, 5*time.Second, "registration", func() bool { return vn.RegistrationID() != "" })
	first := vn.RegistrationID()
	// A new VTN with an empty store: the VEN's polls get 463.
	v2 := vtn.New(vtn.Config{})
	defer v2.Close()
	current.Store(v2)
	eventually(t, 10*time.Second, "registration with the new VTN", func() bool {
		regs, _ := v2.Registrations(ctx)
		return len(regs) == 1 && vn.RegistrationID() != "" && vn.RegistrationID() != first
	})
}
