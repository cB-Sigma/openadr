// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr/internal/testpki"
	"github.com/cB-Sigma/openadr/oadr2b"
	"github.com/cB-Sigma/openadr/oadr2b/vtn"
)

// rawVEN posts hand-built messages to a VTN, as a VEN would.
type rawVEN struct {
	t      *testing.T
	url    string
	client *http.Client
	signer *oadr2b.Signer
}

func (r *rawVEN) send(svc string, so oadr2b.SignedObject) *oadr2b.SignedObject {
	r.t.Helper()
	b, err := oadr2b.Marshal(so)
	if err != nil {
		r.t.Fatal(err)
	}
	if r.signer != nil {
		if b, err = r.signer.Sign(b); err != nil {
			r.t.Fatal(err)
		}
	}
	return r.raw(svc, b)
}

func (r *rawVEN) raw(svc string, b []byte) *oadr2b.SignedObject {
	r.t.Helper()
	ans, _, err := oadr2b.PostXML(context.Background(), r.client, r.url+oadr2b.PathBase+svc, b)
	if err != nil {
		r.t.Fatalf("%s: %v", svc, err)
	}
	so, err := oadr2b.Unmarshal(ans)
	if err != nil {
		r.t.Fatalf("%s answer: %v\n%s", svc, err, ans)
	}
	return so
}

func newVTN(t *testing.T, cfg vtn.Config) (*vtn.VTN, *rawVEN) {
	t.Helper()
	v := vtn.New(cfg)
	srv := httptest.NewServer(v)
	t.Cleanup(func() { srv.Close(); v.Close() })
	return v, &rawVEN{t: t, url: srv.URL, client: srv.Client()}
}

func pull() *bool { b := true; return &b }

// register runs query and create registration and returns venID and
// registrationID.
func (r *rawVEN) register(venName string) (string, string) {
	r.t.Helper()
	q := r.send(oadr2b.ServiceRegisterParty, oadr2b.SignedObject{QueryRegistration: &oadr2b.QueryRegistration{RequestID: "q1"}})
	if q.CreatedPartyRegistration == nil || q.CreatedPartyRegistration.EiResponse.ResponseCode != oadr2b.CodeOK {
		r.t.Fatalf("query: %+v", q)
	}
	c := r.send(oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CreatePartyRegistration: &oadr2b.CreatePartyRegistration{
		RequestID: "r1", ProfileName: "2.0b", TransportName: "simpleHttp", VenName: venName, HTTPPullModel: pull()}})
	cp := c.CreatedPartyRegistration
	if cp == nil || cp.EiResponse.ResponseCode != oadr2b.CodeOK || cp.VenID == "" || cp.RegistrationID == "" {
		r.t.Fatalf("create: %+v", c)
	}
	return cp.VenID, cp.RegistrationID
}

func (r *rawVEN) poll(venID string) *oadr2b.SignedObject {
	r.t.Helper()
	return r.send(oadr2b.ServicePoll, oadr2b.SignedObject{Poll: &oadr2b.Poll{VenID: venID}})
}

func code(so *oadr2b.SignedObject) string {
	switch {
	case so.Response != nil:
		return so.Response.EiResponse.ResponseCode
	case so.CreatedPartyRegistration != nil:
		return so.CreatedPartyRegistration.EiResponse.ResponseCode
	case so.CanceledPartyRegistration != nil:
		return so.CanceledPartyRegistration.EiResponse.ResponseCode
	case so.RegisteredReport != nil:
		return so.RegisteredReport.EiResponse.ResponseCode
	case so.UpdatedReport != nil:
		return so.UpdatedReport.EiResponse.ResponseCode
	case so.CreatedOpt != nil:
		return so.CreatedOpt.EiResponse.ResponseCode
	case so.CanceledOpt != nil:
		return so.CanceledOpt.EiResponse.ResponseCode
	case so.CreatedReport != nil:
		return so.CreatedReport.EiResponse.ResponseCode
	}
	return "?" + oadr2b.MessageName(so)
}

func simple(id string, level float64) oadr2b.OadrEvent {
	return vtn.EventSpec{ID: id, MarketContext: "http://mc.test", Start: time.Now().Add(-time.Minute),
		Intervals: []vtn.IntervalSpec{{Duration: time.Hour, Value: level}}}.Build()
}

func TestRegistration(t *testing.T) {
	var got vtn.RegistrationInfo
	v, ven := newVTN(t, vtn.Config{VtnID: "vtn-1", PollFreq: 3 * time.Second,
		OnCreatePartyRegistration: func(_ context.Context, info vtn.RegistrationInfo) (string, string, error) {
			got = info
			return "ven-" + info.VenName, "", nil
		}})
	q := ven.send(oadr2b.ServiceRegisterParty, oadr2b.SignedObject{QueryRegistration: &oadr2b.QueryRegistration{RequestID: "q1"}})
	cp := q.CreatedPartyRegistration
	if cp == nil || cp.VtnID != "vtn-1" || cp.PollFreq == nil || cp.PollFreq.Duration != "PT3S" || cp.RegistrationID != "" ||
		len(cp.Profiles.Profile) == 0 || cp.Profiles.Profile[0].Name != "2.0b" || cp.EiResponse.RequestID != "q1" {
		t.Fatalf("query answer: %+v", q)
	}
	venID, regID := ven.register("a")
	if venID != "ven-a" || got.VenName != "a" || !got.HTTPPullModel {
		t.Fatalf("registered %q, callback saw %+v", venID, got)
	}
	reg, err := v.Registration(context.Background(), venID)
	if err != nil || reg == nil || reg.RegistrationID != regID {
		t.Fatalf("stored registration %+v, %v", reg, err)
	}
	// A re-registration with an unknown registrationID is 452; with the
	// right one it keeps the IDs.
	bad := ven.send(oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CreatePartyRegistration: &oadr2b.CreatePartyRegistration{
		RequestID: "r2", RegistrationID: "nope", VenID: venID, ProfileName: "2.0b", TransportName: "simpleHttp", HTTPPullModel: pull()}})
	if code(bad) != oadr2b.CodeInvalidID {
		t.Fatalf("unknown registrationID: %+v", bad)
	}
	again := ven.send(oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CreatePartyRegistration: &oadr2b.CreatePartyRegistration{
		RequestID: "r3", RegistrationID: regID, VenID: venID, ProfileName: "2.0b", TransportName: "simpleHttp", HTTPPullModel: pull()}})
	if code(again) != oadr2b.CodeOK || again.CreatedPartyRegistration.RegistrationID != regID {
		t.Fatalf("re-registration: %+v", again)
	}
	// A message for another venID is refused.
	if c := code(ven.poll("someone-else")); c != oadr2b.CodeNotRegistered {
		t.Fatalf("poll of an unknown VEN: %s", c)
	}
	can := ven.send(oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CancelPartyRegistration: &oadr2b.CancelPartyRegistration{
		RequestID: "c1", RegistrationID: regID, VenID: venID}})
	if code(can) != oadr2b.CodeOK {
		t.Fatalf("cancel: %+v", can)
	}
	if c := code(ven.poll(venID)); c != oadr2b.CodeNotRegistered {
		t.Fatalf("poll after cancel: %s", c)
	}
}

func TestRefusedRegistration(t *testing.T) {
	_, ven := newVTN(t, vtn.Config{OnCreatePartyRegistration: func(context.Context, vtn.RegistrationInfo) (string, string, error) {
		return "", "", vtn.Refuse(oadr2b.CodeNotAllowed, "not on the list")
	}})
	c := ven.send(oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CreatePartyRegistration: &oadr2b.CreatePartyRegistration{
		RequestID: "r1", ProfileName: "2.0b", TransportName: "simpleHttp", HTTPPullModel: pull()}})
	if code(c) != oadr2b.CodeNotAllowed {
		t.Fatalf("refused registration: %+v", c)
	}
}

func TestEventsByPoll(t *testing.T) {
	type answer struct{ ven, event, opt string }
	var mu sync.Mutex
	var answers []answer
	v, ven := newVTN(t, vtn.Config{VtnID: "vtn-1", OnEventResponse: func(_ context.Context, venID, eventID, optType string) {
		mu.Lock()
		answers = append(answers, answer{venID, eventID, optType})
		mu.Unlock()
	}})
	venID, _ := ven.register("a")
	if got := ven.poll(venID); got.Response == nil {
		t.Fatalf("empty poll: %s", oadr2b.MessageName(got))
	}
	if err := v.AddEvent(venID, simple("ev-1", 2)); err != nil {
		t.Fatal(err)
	}
	if err := v.AddEvent(venID, simple("ev-1", 2)); err == nil {
		t.Fatal("the same eventID added twice")
	}
	if err := v.AddEvent("nobody", simple("ev-x", 1)); err == nil {
		t.Fatal("event for an unregistered VEN")
	}
	de := ven.poll(venID).DistributeEvent
	if de == nil || len(de.Events) != 1 || de.VtnID != "vtn-1" {
		t.Fatalf("distribution: %+v", de)
	}
	e := de.Events[0].EiEvent
	if e.Descriptor.EventStatus != "active" || e.Target.VenID[0] != venID || de.Events[0].ResponseRequired != "always" {
		t.Fatalf("event: %+v", e)
	}
	if got := ven.poll(venID); got.Response == nil {
		t.Fatalf("poll after distribution: %s", oadr2b.MessageName(got))
	}
	created := func(mod uint32, opt string) *oadr2b.SignedObject {
		return ven.send(oadr2b.ServiceEvent, oadr2b.SignedObject{CreatedEvent: &oadr2b.CreatedEvent{EiCreatedEvent: oadr2b.EiCreatedEvent{
			EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK}, VenID: venID,
			EventResponses: &oadr2b.EventResponses{Response: []oadr2b.EventResponse{{ResponseCode: oadr2b.CodeOK, RequestID: de.RequestID,
				QualifiedEventID: oadr2b.QualifiedEventID{EventID: "ev-1", ModificationNumber: mod}, OptType: opt}}}}}})
	}
	if c := code(created(0, "optIn")); c != oadr2b.CodeOK {
		t.Fatalf("created event: %s", c)
	}
	if c := code(created(5, "optIn")); c != oadr2b.CodeOutOfSequence {
		t.Fatalf("stale modification number: %s", c)
	}
	if v.OptState(venID, "ev-1") != "optIn" {
		t.Fatalf("opt state %q", v.OptState(venID, "ev-1"))
	}

	// Modify: the number goes up and the VEN gets the new list.
	ev := simple("ev-1", 3)
	if err := v.ModifyEvent(venID, ev); err != nil {
		t.Fatal(err)
	}
	de = ven.poll(venID).DistributeEvent
	if de == nil || de.Events[0].EiEvent.Descriptor.ModificationNumber != 1 ||
		de.Events[0].EiEvent.Signals.Signal[0].Intervals.Interval[0].SignalPayload.PayloadFloat.Value != 3 {
		t.Fatalf("modified: %+v", de)
	}
	if err := v.CancelEvent(venID, "ev-1"); err != nil {
		t.Fatal(err)
	}
	de = ven.poll(venID).DistributeEvent
	if de == nil || de.Events[0].EiEvent.Descriptor.EventStatus != "cancelled" || de.Events[0].EiEvent.Descriptor.ModificationNumber != 2 {
		t.Fatalf("cancelled: %+v", de)
	}
	if c := code(created(2, "optOut")); c != oadr2b.CodeOK {
		t.Fatalf("ack of cancellation: %s", c)
	}
	// Once acknowledged, the cancelled event is no longer sent.
	re := ven.send(oadr2b.ServiceEvent, oadr2b.SignedObject{RequestEvent: &oadr2b.RequestEvent{EiRequestEvent: oadr2b.EiRequestEvent{RequestID: "re", VenID: venID}}})
	if re.DistributeEvent == nil || len(re.DistributeEvent.Events) != 0 {
		t.Fatalf("after the acknowledged cancellation: %+v", re)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(answers) != 2 || answers[0] != (answer{venID, "ev-1", "optIn"}) || answers[1].opt != "optOut" {
		t.Fatalf("callbacks: %+v", answers)
	}
}

func TestOpts(t *testing.T) {
	var opts []string
	v, ven := newVTN(t, vtn.Config{OnCreateOpt: func(_ context.Context, venID string, o *oadr2b.CreateOpt) error {
		opts = append(opts, venID+" "+o.OptID+" "+o.OptType)
		return nil
	}})
	venID, _ := ven.register("a")
	if err := v.AddEvent(venID, simple("ev-1", 1)); err != nil {
		t.Fatal(err)
	}
	opt := func(id, event string) *oadr2b.SignedObject {
		return ven.send(oadr2b.ServiceOpt, oadr2b.SignedObject{CreateOpt: &oadr2b.CreateOpt{OptID: id, OptType: "optOut", OptReason: "participating",
			VenID: venID, CreatedDateTime: oadr2b.FormatTime(time.Now()), RequestID: "o-" + id,
			QualifiedEventID: &oadr2b.QualifiedEventID{EventID: event}, Target: oadr2b.Target{VenID: []string{venID}}}})
	}
	if c := code(opt("opt-1", "ev-1")); c != oadr2b.CodeOK {
		t.Fatalf("create opt: %s", c)
	}
	if c := code(opt("opt-2", "ev-unknown")); c != oadr2b.CodeInvalidID {
		t.Fatalf("opt for an unknown event: %s", c)
	}
	if v.OptState(venID, "ev-1") != "optOut" {
		t.Fatalf("opt state %q", v.OptState(venID, "ev-1"))
	}
	cancel := func(id string) string {
		return code(ven.send(oadr2b.ServiceOpt, oadr2b.SignedObject{CancelOpt: &oadr2b.CancelOpt{RequestID: "co", OptID: id, VenID: venID}}))
	}
	if c := cancel("opt-1"); c != oadr2b.CodeOK {
		t.Fatalf("cancel opt: %s", c)
	}
	if c := cancel("opt-1"); c != oadr2b.CodeInvalidID {
		t.Fatalf("cancel of an unknown opt: %s", c)
	}
	if len(opts) != 1 || opts[0] != venID+" opt-1 optOut" {
		t.Fatalf("callbacks: %v", opts)
	}
}

func metadata() []oadr2b.Report {
	rate := &oadr2b.SamplingRate{MinPeriod: "PT10S", MaxPeriod: "PT1H"}
	return []oadr2b.Report{{ReportSpecifierID: "usage", ReportName: "METADATA_TELEMETRY_USAGE", ReportRequestID: "0",
		CreatedDateTime: oadr2b.FormatTime(time.Now()), Duration: &oadr2b.DurationProp{Duration: "PT1H"},
		Descriptions: []oadr2b.ReportDescription{{RID: "power", ReportType: "usage", ReadingType: "Direct Read", SamplingRate: rate,
			ItemBase: &oadr2b.ItemBase{XMLName: oadr2b.XMLName(oadr2b.NSPower, "powerReal"), ItemDescription: "RealPower", ItemUnits: "W"}}}}}
}

func TestReports(t *testing.T) {
	var mu sync.Mutex
	var values []float64
	v, ven := newVTN(t, vtn.Config{
		OnRegisterReport: func(_ context.Context, _ string, reports []oadr2b.Report) []oadr2b.ReportRequest {
			return vtn.RequestAll(reports, time.Second, time.Minute)
		},
		OnUpdateReport: func(_ context.Context, _ string, reports []oadr2b.Report) error {
			mu.Lock()
			defer mu.Unlock()
			for _, r := range reports {
				for _, iv := range r.Intervals.Interval {
					for _, p := range iv.ReportPayload {
						values = append(values, p.PayloadFloat.Value)
					}
				}
			}
			return nil
		},
	})
	venID, _ := ven.register("a")
	rr := ven.send(oadr2b.ServiceReport, oadr2b.SignedObject{RegisterReport: &oadr2b.RegisterReport{RequestID: "rr", Reports: metadata(), VenID: venID}})
	reqs := rr.RegisteredReport.ReportRequests
	if code(rr) != oadr2b.CodeOK || len(reqs) != 1 || reqs[0].ReportSpecifier.Granularity.Duration != "PT10S" ||
		reqs[0].ReportSpecifier.SpecifierPayloads[0].RID != "power" {
		t.Fatalf("registered report: %+v", rr.RegisteredReport)
	}
	if m := v.Metadata(venID); len(m) != 1 || m[0].ReportSpecifierID != "usage" {
		t.Fatalf("metadata %+v", m)
	}
	update := func(reqID string, val float64) *oadr2b.SignedObject {
		start := &oadr2b.DtStart{DateTime: oadr2b.FormatTime(time.Now())}
		return ven.send(oadr2b.ServiceReport, oadr2b.SignedObject{UpdateReport: &oadr2b.UpdateReport{RequestID: "u", VenID: venID, Reports: []oadr2b.Report{{
			DtStart: start, ReportRequestID: reqID, ReportSpecifierID: "usage", ReportName: "TELEMETRY_USAGE", CreatedDateTime: start.DateTime,
			Intervals: &oadr2b.Intervals{Interval: []oadr2b.Interval{{DtStart: start, Duration: &oadr2b.DurationProp{Duration: "PT10S"},
				ReportPayload: []oadr2b.ReportPayload{{RID: "power", PayloadFloat: &oadr2b.PayloadFloat{Value: val}}}}}}}}}})
	}
	if c := code(update(reqs[0].ReportRequestID, 640)); c != oadr2b.CodeOK {
		t.Fatalf("update: %s", c)
	}
	if c := code(update("unknown", 1)); c != oadr2b.CodeInvalidID {
		t.Fatalf("update for an unknown request: %s", c)
	}
	// A request made later goes out on the next poll.
	if err := v.RequestReport(venID, vtn.NewReportRequest("usage", []string{"power"}, 10*time.Second, 0)); err != nil {
		t.Fatal(err)
	}
	if err := v.RequestReport(venID, vtn.NewReportRequest("nothing", nil, 0, 0)); err == nil {
		t.Fatal("request for a report the VEN does not offer")
	}
	cr := ven.poll(venID).CreateReport
	if cr == nil || len(cr.ReportRequests) != 1 {
		t.Fatalf("create report: %+v", cr)
	}
	created := ven.send(oadr2b.ServiceReport, oadr2b.SignedObject{CreatedReport: &oadr2b.CreatedReport{
		EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, RequestID: cr.RequestID}, VenID: venID}})
	if code(created) != oadr2b.CodeOK {
		t.Fatalf("created report: %+v", created)
	}
	if err := v.CancelReport(venID, []string{reqs[0].ReportRequestID}, false); err != nil {
		t.Fatal(err)
	}
	can := ven.poll(venID).CancelReport
	if can == nil || can.ReportRequestID[0] != reqs[0].ReportRequestID {
		t.Fatalf("cancel report: %+v", can)
	}
	// A report still sent for it is answered with the cancellation again.
	ur := update(reqs[0].ReportRequestID, 1).UpdatedReport
	if ur == nil || ur.CancelReport == nil || ur.CancelReport.ReportRequestID[0] != reqs[0].ReportRequestID {
		t.Fatalf("update after cancel: %+v", ur)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(values) != 1 || values[0] != 640 {
		t.Fatalf("values %v", values)
	}
}

func TestReregisterAndCancelByVTN(t *testing.T) {
	var cancelled []string
	v, ven := newVTN(t, vtn.Config{OnCancelPartyRegistration: func(_ context.Context, r vtn.Registration) {
		cancelled = append(cancelled, r.VenID)
	}})
	venID, regID := ven.register("a")
	if err := v.Reregister(venID); err != nil {
		t.Fatal(err)
	}
	if rr := ven.poll(venID).RequestReregistration; rr == nil || rr.VenID != venID {
		t.Fatal("no oadrRequestReregistration")
	}
	if err := v.CancelRegistration(venID); err != nil {
		t.Fatal(err)
	}
	cp := ven.poll(venID).CancelPartyRegistration
	if cp == nil || cp.RegistrationID != regID {
		t.Fatalf("cancel: %+v", cp)
	}
	ans := ven.send(oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CanceledPartyRegistration: &oadr2b.CanceledPartyRegistration{
		EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, RequestID: cp.RequestID}, RegistrationID: regID, VenID: venID}})
	if code(ans) != oadr2b.CodeOK {
		t.Fatalf("canceled answer: %+v", ans)
	}
	if c := code(ven.poll(venID)); c != oadr2b.CodeNotRegistered {
		t.Fatalf("poll after the VTN cancelled: %s", c)
	}
	if len(cancelled) != 1 || cancelled[0] != venID {
		t.Fatalf("callbacks %v", cancelled)
	}
}

// A VEN that registers for push gets the events posted to its own
// endpoint, and its oadrCreatedEvent in the answer is taken.
func TestPush(t *testing.T) {
	opted := make(chan string, 4)
	v, ven := newVTN(t, vtn.Config{PushRetry: 50 * time.Millisecond, OnEventResponse: func(_ context.Context, _, eventID, optType string) {
		opted <- eventID + " " + optType
	}})
	var venID string
	var mu sync.Mutex
	fails := 1
	push := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fail := fails > 0
		fails--
		id := venID
		mu.Unlock()
		if fail {
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		body, _ := io.ReadAll(r.Body)
		so, err := oadr2b.Unmarshal(body)
		if err != nil || so.DistributeEvent == nil || r.URL.Path != oadr2b.PathBase+oadr2b.ServiceEvent {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		e := so.DistributeEvent.Events[0].EiEvent.Descriptor
		b, _ := oadr2b.Marshal(oadr2b.SignedObject{CreatedEvent: &oadr2b.CreatedEvent{EiCreatedEvent: oadr2b.EiCreatedEvent{
			EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK}, VenID: id,
			EventResponses: &oadr2b.EventResponses{Response: []oadr2b.EventResponse{{ResponseCode: oadr2b.CodeOK, RequestID: so.DistributeEvent.RequestID,
				QualifiedEventID: oadr2b.QualifiedEventID{EventID: e.EventID, ModificationNumber: e.ModificationNumber}, OptType: "optIn"}}}}}})
		oadr2b.WriteXML(w, r, b)
	}))
	defer push.Close()
	no := false
	c := ven.send(oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CreatePartyRegistration: &oadr2b.CreatePartyRegistration{
		RequestID: "r1", ProfileName: "2.0b", TransportName: "simpleHttp", TransportAddress: push.URL, HTTPPullModel: &no}})
	if code(c) != oadr2b.CodeOK {
		t.Fatalf("push registration: %+v", c)
	}
	mu.Lock()
	venID = c.CreatedPartyRegistration.VenID
	mu.Unlock()
	if err := v.AddEvent(venID, simple("ev-p", 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-opted:
		if got != "ev-p optIn" {
			t.Fatalf("opt %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no oadrCreatedEvent from the push answer")
	}
}

func TestSignaturesAndTLSIdentity(t *testing.T) {
	pki := testpki.New(t)
	vtnLeaf := pki.Issue(t, "vtn", "127.0.0.1")
	venLeaf := pki.Issue(t, "ven")
	other := pki.Issue(t, "other")
	vtnSigner, _ := oadr2b.NewSigner(vtnLeaf.TLS)
	v := vtn.New(vtn.Config{Signer: vtnSigner, RequireSignatures: true})
	defer v.Close()
	tc, err := vtn.ServerTLSConfig(oadr2b.TLSProfileOpenADR, pki.Pool, vtnLeaf.TLS)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(v)
	srv.TLS = tc
	srv.StartTLS()
	defer srv.Close()
	client := func(leaf testpki.Leaf) *http.Client {
		c := &tls.Config{RootCAs: pki.Pool, Certificates: []tls.Certificate{leaf.TLS}}
		if err := oadr2b.ApplyTLSProfile(c, oadr2b.TLSProfileOpenADR); err != nil {
			t.Fatal(err)
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: c}}
	}
	venSigner, _ := oadr2b.NewSigner(venLeaf.TLS)
	ven := &rawVEN{t: t, url: srv.URL, client: client(venLeaf), signer: venSigner}
	venID, _ := ven.register("signed")
	reg, _ := v.Registration(context.Background(), venID)
	if reg.Fingerprint != oadr2b.Fingerprint(venLeaf.TLS.Certificate[0]) {
		t.Fatalf("fingerprint %q", reg.Fingerprint)
	}
	if got := ven.poll(venID); got.Response == nil || got.Response.EiResponse.ResponseCode != oadr2b.CodeOK {
		t.Fatalf("signed poll: %+v", got)
	}
	// Unsigned, replayed, and signed by another certificate: refused.
	unsigned := &rawVEN{t: t, url: srv.URL, client: client(venLeaf)}
	if c := code(unsigned.poll(venID)); c != oadr2b.CodeBadSignature {
		t.Fatalf("unsigned: %s", c)
	}
	b, _ := oadr2b.Marshal(oadr2b.SignedObject{Poll: &oadr2b.Poll{VenID: venID}})
	b, _ = venSigner.Sign(b)
	if c := code(ven.raw(oadr2b.ServicePoll, b)); c != oadr2b.CodeOK {
		t.Fatalf("first: %s", c)
	}
	if c := code(ven.raw(oadr2b.ServicePoll, b)); c != oadr2b.CodeBadSignature {
		t.Fatalf("replay: %s", c)
	}
	otherSigner, _ := oadr2b.NewSigner(other.TLS)
	wrong := &rawVEN{t: t, url: srv.URL, client: client(venLeaf), signer: otherSigner}
	if c := code(wrong.poll(venID)); c != oadr2b.CodeBadSignature {
		t.Fatalf("signed by another certificate: %s", c)
	}
	// Another client certificate cannot speak for this VEN.
	otherSigned := &rawVEN{t: t, url: srv.URL, client: client(other), signer: otherSigner}
	if c := code(otherSigned.poll(venID)); c != oadr2b.CodeNotRegistered && c != oadr2b.CodeInvalidID {
		t.Fatalf("another certificate: %s", c)
	}
	// Answers are signed by the VTN.
	ans, _, err := oadr2b.PostXML(context.Background(), client(venLeaf), srv.URL+oadr2b.PathBase+oadr2b.ServicePoll, mustSign(t, venSigner, venID))
	if err != nil {
		t.Fatal(err)
	}
	vf, err := oadr2b.VerifyPayload(ans)
	if err != nil || oadr2b.Fingerprint(vf.Cert.Raw) != vtnSigner.Fingerprint() {
		t.Fatalf("answer signature: %v", err)
	}
}

func mustSign(t *testing.T, s *oadr2b.Signer, venID string) []byte {
	b, err := oadr2b.Marshal(oadr2b.SignedObject{Poll: &oadr2b.Poll{VenID: venID}})
	if err == nil {
		b, err = s.Sign(b)
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTransportErrors(t *testing.T) {
	_, ven := newVTN(t, vtn.Config{})
	resp, err := ven.client.Get(ven.url + oadr2b.PathBase + oadr2b.ServicePoll)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
	_, _, err = oadr2b.PostXML(context.Background(), ven.client, ven.url+oadr2b.PathBase+oadr2b.ServicePoll, []byte("<nope/>"))
	var he *oadr2b.HTTPError
	if !errors.As(err, &he) || he.Status != http.StatusNotAcceptable {
		t.Fatalf("bad payload: %v", err)
	}
	_, _, err = oadr2b.PostXML(context.Background(), ven.client, ven.url+"/elsewhere", []byte("<nope/>"))
	if !errors.As(err, &he) || he.Status != http.StatusNotFound {
		t.Fatalf("unknown path: %v", err)
	}
	// A message sent to the wrong service is 454.
	if c := code(ven.send(oadr2b.ServiceEvent, oadr2b.SignedObject{Poll: &oadr2b.Poll{VenID: "x"}})); c != oadr2b.CodeInvalidData {
		t.Fatalf("wrong service: %s", c)
	}
}

// Many VENs register, get events and answer them at once.
func TestManyVENs(t *testing.T) {
	var mu sync.Mutex
	got := map[string]bool{}
	v, ven := newVTN(t, vtn.Config{OnEventResponse: func(_ context.Context, venID, _, _ string) {
		mu.Lock()
		got[venID] = true
		mu.Unlock()
	}})
	const n = 30
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := &rawVEN{t: t, url: ven.url, client: ven.client}
			venID, _ := r.register(fmt.Sprint("ven", i))
			if err := v.AddEvent(venID, simple("ev-"+venID, float64(i))); err != nil {
				errs <- err
				return
			}
			de := r.poll(venID).DistributeEvent
			if de == nil || len(de.Events) != 1 {
				errs <- fmt.Errorf("%s: no distribution", venID)
				return
			}
			d := de.Events[0].EiEvent.Descriptor
			r.send(oadr2b.ServiceEvent, oadr2b.SignedObject{CreatedEvent: &oadr2b.CreatedEvent{EiCreatedEvent: oadr2b.EiCreatedEvent{
				EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK}, VenID: venID,
				EventResponses: &oadr2b.EventResponses{Response: []oadr2b.EventResponse{{ResponseCode: oadr2b.CodeOK, RequestID: de.RequestID,
					QualifiedEventID: oadr2b.QualifiedEventID{EventID: d.EventID, ModificationNumber: d.ModificationNumber}, OptType: "optIn"}}}}}})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	regs, err := v.Registrations(context.Background())
	if err != nil || len(regs) != n {
		t.Fatalf("%d registrations, %v", len(regs), err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != n {
		t.Fatalf("%d VENs answered", len(got))
	}
}

func TestEventStatus(t *testing.T) {
	now := time.Now()
	ev := vtn.EventSpec{ID: "e", Start: now.Add(time.Hour), RampUp: 2 * time.Hour, Intervals: []vtn.IntervalSpec{{Duration: time.Hour, Value: 1}}}.Build()
	for _, c := range []struct {
		at   time.Time
		want string
	}{{now.Add(-2 * time.Hour), "far"}, {now, "near"}, {now.Add(90 * time.Minute), "active"}, {now.Add(3 * time.Hour), "completed"}} {
		if got := vtn.Status(ev.EiEvent, c.at); got != c.want {
			t.Errorf("at %s: %s, want %s", c.at, got, c.want)
		}
	}
}
