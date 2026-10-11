// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package ven is a ready OpenADR 2.0b VEN client for the simple-HTTP
// transport.
//
// Run registers with the VTN (oadrQueryRegistration, then
// oadrCreatePartyRegistration), announces the VEN's reports (its METADATA,
// from Config.Reports), asks for the current events and then polls at the
// frequency the VTN asks for, or, with Config.PushListen, serves the push
// endpoints the VTN posts to. Events go to Config.OnEvent, whose answer
// (optIn or optOut) is sent in oadrCreatedEvent. Report requests are
// accepted when they name data points of the METADATA; their data is read
// with Config.ReadData every granularity and sent in oadrUpdateReport
// every reportBackDuration. Re-registration requests, cancellations from
// the VTN, report cancellations and opts (CreateOpt, OptEvent, CancelOpt)
// are handled. Payloads can be signed, and the VTN's signatures required.
//
// Clause references are to the OpenADR 2.0b profile specification and its
// conformance rules.
package ven

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// Config configures a VEN. Only VTNURL is required.
type Config struct {
	// VTNURL is the VTN's base URL with any prefix
	// ("https://vtn.example:8443/oadr"); the simple-HTTP path
	// /OpenADR2/Simple/2.0b/<service> is added unless it is there.
	VTNURL string
	// VenID is the venID to register with, if the VTN gave one out of
	// band; the VTN's answer decides.
	VenID   string
	VenName string
	// HTTPClient sends to the VTN (default: a client with a 10 s timeout
	// and TLS from Certificate, RootCAs and TLSProfile).
	HTTPClient *http.Client
	// Certificate is the VEN's TLS client certificate (and push server
	// certificate); RootCAs check the VTN (and, for push, the VTN's
	// client certificate). TLSProfile is oadr2b.TLSProfileCompatible
	// (default) or oadr2b.TLSProfileOpenADR.
	Certificate *tls.Certificate
	RootCAs     *x509.CertPool
	TLSProfile  string
	// Signer, when set, signs every payload sent.
	Signer *oadr2b.Signer
	// RequireSignatures refuses VTN payloads that are not signed by
	// VTNFingerprint (default: the VTN's TLS server certificate) or are
	// replayed.
	RequireSignatures bool
	VTNFingerprint    string
	Guard             *oadr2b.ReplayGuard
	// PollFreq overrides the poll frequency the VTN asks for (which is
	// used when this is zero, but not below one second; default 10 s).
	PollFreq time.Duration
	// PushListen, when set, makes the VEN register for push and serve the
	// VTN's pushes on this address ("127.0.0.1:0" picks a port).
	// PushURL is the oadrTransportAddress to register (default:
	// scheme://the listener's address). PushTLS serves the push endpoint
	// (default: Certificate, with client certificates required and
	// checked against RootCAs; plain HTTP without a Certificate).
	PushListen string
	PushURL    string
	PushTLS    *tls.Config
	// Reports is the METADATA this VEN offers: reports named
	// METADATA_<name> with a reportSpecifierID and one description per
	// data point (rID).
	Reports    []oadr2b.Report
	ReportOnly bool
	// Validate, when set, checks every payload received (a schema check).
	Validate func([]byte) error
	// Logger receives warnings (default: discarded).
	Logger *slog.Logger

	// OnEvent is called for each new or modified event (a new
	// modificationNumber, including cancellation) and returns optIn or
	// optOut ("" is optIn; without OnEvent every event is opted in).
	OnEvent func(ctx context.Context, ev oadr2b.OadrEvent) string
	// ReadData reads one data point of a requested report at time at; ok
	// false sends a placeholder marked bad quality. The payload's RID is
	// filled in. Without it every value is such a placeholder.
	ReadData func(ctx context.Context, reportSpecifierID, rID string, at time.Time) (p oadr2b.ReportPayload, ok bool)
	// OnRegistered is told of each registration (and re-registration).
	OnRegistered func(ctx context.Context, r Registration)
	// OnUnregistered is told when the VTN ended the registration; Run
	// registers again after a pause.
	OnUnregistered func(ctx context.Context)
}

// Registration is the VEN's registration with its VTN.
type Registration struct {
	VenID, RegistrationID, VtnID string
	// PollFreq is the poll frequency in use.
	PollFreq time.Duration
}

// VEN is an OpenADR 2.0b VEN. Create it with New.
type VEN struct {
	cfg    Config
	log    *slog.Logger
	client *http.Client
	guard  *oadr2b.ReplayGuard
	wg     sync.WaitGroup

	mu        sync.Mutex
	regID     string
	venID     string
	vtnID     string
	pollEvery time.Duration
	events    map[string]*venEvent
	order     []string
	requests  map[string]*request
	optIDs    map[string]string // optID → eventID
	pushURL   string
	quit      bool // the VEN cancelled its registration: Run stops
	wake      chan struct{}
	runCtx    context.Context
}

type venEvent struct {
	ev  oadr2b.OadrEvent
	opt string
}

// New checks cfg and creates a VEN (no I/O).
func New(cfg Config) (*VEN, error) {
	if cfg.VTNURL == "" {
		return nil, errors.New("ven: VTNURL is required")
	}
	v := &VEN{cfg: cfg, log: cfg.Logger, client: cfg.HTTPClient, guard: cfg.Guard, venID: cfg.VenID,
		events: map[string]*venEvent{}, requests: map[string]*request{}, optIDs: map[string]string{}, wake: make(chan struct{}, 1)}
	if v.log == nil {
		v.log = slog.New(slog.DiscardHandler)
	}
	if v.guard == nil {
		v.guard = &oadr2b.ReplayGuard{}
	}
	if v.client == nil {
		tc := &tls.Config{RootCAs: cfg.RootCAs}
		if err := oadr2b.ApplyTLSProfile(tc, cfg.TLSProfile); err != nil {
			return nil, err
		}
		if cfg.Certificate != nil {
			tc.Certificates = []tls.Certificate{*cfg.Certificate}
		}
		v.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment}}
	}
	for _, rep := range cfg.Reports {
		if rep.ReportSpecifierID == "" {
			return nil, errors.New("ven: every report needs a reportSpecifierID")
		}
	}
	return v, nil
}

func newID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// VenID is the venID in use (the VTN's once registered).
func (v *VEN) VenID() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.venID
}

// RegistrationID is the current registrationID, "" when not registered.
func (v *VEN) RegistrationID() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.regID
}

// PollEvery is the poll frequency in use.
func (v *VEN) PollEvery() time.Duration {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case v.cfg.PollFreq > 0:
		return v.cfg.PollFreq
	case v.pollEvery > 0:
		return v.pollEvery
	}
	return 10 * time.Second
}

// Events lists the current events in the order the VTN sent them.
func (v *VEN) Events() []oadr2b.OadrEvent {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]oadr2b.OadrEvent, 0, len(v.order))
	for _, id := range v.order {
		out = append(out, v.events[id].ev)
	}
	return out
}

// Opt is the VEN's answer to an event: optIn, optOut or "" (unknown).
func (v *VEN) Opt(eventID string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if e := v.events[eventID]; e != nil {
		return e.opt
	}
	return ""
}

// ReportRequests lists the active report requests by reportRequestID.
func (v *VEN) ReportRequests() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for id := range v.requests {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// ---- sending ----------------------------------------------------------------

// endpoint is the URL of a VTN service.
func (v *VEN) endpoint(svc string) string {
	u := strings.TrimRight(v.cfg.VTNURL, "/")
	if strings.HasSuffix(u, strings.TrimRight(oadr2b.PathBase, "/")) {
		return u + "/" + svc
	}
	return u + oadr2b.PathBase + svc
}

func (v *VEN) encode(so oadr2b.SignedObject) ([]byte, error) {
	b, err := oadr2b.Marshal(so)
	if err != nil || v.cfg.Signer == nil {
		return b, err
	}
	return v.cfg.Signer.Sign(b)
}

// check validates and verifies a payload from the VTN.
func (v *VEN) check(b []byte, state *tls.ConnectionState) error {
	if v.cfg.Validate != nil {
		if err := v.cfg.Validate(b); err != nil {
			return err
		}
	}
	return v.verify(b, state)
}

// verify applies RequireSignatures: signed by VTNFingerprint, else by
// the VTN's TLS certificate (server, or client for a push), not replayed.
func (v *VEN) verify(b []byte, state *tls.ConnectionState) error {
	if !v.cfg.RequireSignatures {
		return nil
	}
	got, err := oadr2b.VerifyPayload(b)
	if err != nil {
		return fmt.Errorf("XML signature: %w", err)
	}
	want := v.cfg.VTNFingerprint
	if want == "" && state != nil && len(state.PeerCertificates) > 0 {
		want = oadr2b.Fingerprint(state.PeerCertificates[0].Raw)
	}
	if fp := oadr2b.Fingerprint(got.Cert.Raw); want != "" && !strings.EqualFold(fp, want) {
		return fmt.Errorf("XML signature by %s, the VTN is %s", fp, want)
	}
	return v.guard.Check(got)
}

// Send posts one message to a VTN service and returns the VTN's answer
// (nil for an empty one). Most callers use the other methods.
func (v *VEN) Send(ctx context.Context, service string, so oadr2b.SignedObject) (*oadr2b.SignedObject, error) {
	b, err := v.encode(so)
	if err != nil {
		return nil, err
	}
	ans, state, err := oadr2b.PostXML(ctx, v.client, v.endpoint(service), b)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(ans)) == 0 {
		return nil, nil
	}
	if err := v.check(ans, state); err != nil {
		return nil, fmt.Errorf("the VTN's answer: %w", err)
	}
	return oadr2b.Unmarshal(ans)
}

// codeOf is the response code and description of an answer.
func codeOf(so *oadr2b.SignedObject) (string, string) {
	if so == nil {
		return "", "no answer"
	}
	var r *oadr2b.EiResponse
	switch {
	case so.Response != nil:
		r = &so.Response.EiResponse
	case so.CreatedPartyRegistration != nil:
		r = &so.CreatedPartyRegistration.EiResponse
	case so.CanceledPartyRegistration != nil:
		r = &so.CanceledPartyRegistration.EiResponse
	case so.RegisteredReport != nil:
		r = &so.RegisteredReport.EiResponse
	case so.CreatedReport != nil:
		r = &so.CreatedReport.EiResponse
	case so.UpdatedReport != nil:
		r = &so.UpdatedReport.EiResponse
	case so.CanceledReport != nil:
		r = &so.CanceledReport.EiResponse
	case so.CreatedOpt != nil:
		r = &so.CreatedOpt.EiResponse
	case so.CanceledOpt != nil:
		r = &so.CanceledOpt.EiResponse
	case so.DistributeEvent != nil:
		if so.DistributeEvent.EiResponse != nil {
			r = so.DistributeEvent.EiResponse
		} else {
			return oadr2b.CodeOK, ""
		}
	default:
		return "", oadr2b.MessageName(so)
	}
	return r.ResponseCode, r.ResponseDescription
}

func ok(requestID string) oadr2b.EiResponse {
	return oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, ResponseDescription: "OK", RequestID: requestID}
}

func fail(code, desc, requestID string) oadr2b.EiResponse {
	return oadr2b.EiResponse{ResponseCode: code, ResponseDescription: desc, RequestID: requestID}
}

// ---- registration -----------------------------------------------------------

// minPoll is the shortest poll frequency taken from a VTN.
const minPoll = time.Second

// Register registers with the VTN (again with the same registrationID
// when registered: rule 402), announces the METADATA, takes report
// requests that come with the answer and asks for the events (rules 309
// and 405).
func (v *VEN) Register(ctx context.Context) error {
	ans, err := v.Send(ctx, oadr2b.ServiceRegisterParty, oadr2b.SignedObject{QueryRegistration: &oadr2b.QueryRegistration{RequestID: newID("q-")}})
	if err != nil {
		return fmt.Errorf("query registration: %w", err)
	}
	if c, msg := codeOf(ans); c != oadr2b.CodeOK || ans.CreatedPartyRegistration == nil {
		return fmt.Errorf("query registration: %s %s", c, msg)
	}
	v.mu.Lock()
	cpr := &oadr2b.CreatePartyRegistration{RequestID: newID("r-"), RegistrationID: v.regID, VenID: v.venID, ProfileName: oadr2b.Profile20b,
		TransportName: oadr2b.TransportName, ReportOnly: v.cfg.ReportOnly, XMLSignature: v.cfg.Signer != nil, VenName: v.cfg.VenName}
	pull := v.pushURL == ""
	cpr.HTTPPullModel = &pull
	if !pull {
		cpr.TransportAddress = v.pushURL
	}
	again := v.regID != ""
	v.mu.Unlock()
	ans, err = v.Send(ctx, oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CreatePartyRegistration: cpr})
	if err != nil {
		return fmt.Errorf("create registration: %w", err)
	}
	if c, msg := codeOf(ans); c != oadr2b.CodeOK || ans.CreatedPartyRegistration == nil {
		if again {
			// The VTN no longer knows the registration: register anew.
			v.mu.Lock()
			v.regID = ""
			v.mu.Unlock()
			return v.Register(ctx)
		}
		return fmt.Errorf("create registration: %s %s", c, msg)
	}
	got := ans.CreatedPartyRegistration
	if got.RegistrationID == "" || got.VenID == "" {
		return errors.New("create registration: the VTN gave no registrationID or venID")
	}
	v.mu.Lock()
	v.regID, v.venID, v.vtnID = got.RegistrationID, got.VenID, got.VtnID
	if got.PollFreq != nil {
		if p, err := oadr2b.ParseDuration(got.PollFreq.Duration); err == nil && p > 0 {
			v.pollEvery = max(p, minPoll)
		}
	}
	// Rule 407: a registration starts without report requests.
	v.requests = map[string]*request{}
	v.mu.Unlock()
	if err := v.registerReports(ctx, ""); err != nil {
		return err
	}
	if err := v.requestEvents(ctx); err != nil {
		return err
	}
	if v.cfg.OnRegistered != nil {
		v.cfg.OnRegistered(ctx, Registration{VenID: got.VenID, RegistrationID: got.RegistrationID, VtnID: got.VtnID, PollFreq: v.PollEvery()})
	}
	return nil
}

// CancelRegistration ends the registration with the VTN; Run then
// returns.
func (v *VEN) CancelRegistration(ctx context.Context) error {
	v.mu.Lock()
	regID, venID := v.regID, v.venID
	v.mu.Unlock()
	if regID == "" {
		return errors.New("not registered")
	}
	ans, err := v.Send(ctx, oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CancelPartyRegistration: &oadr2b.CancelPartyRegistration{
		RequestID: newID("c-"), RegistrationID: regID, VenID: venID}})
	if err != nil {
		return err
	}
	if c, msg := codeOf(ans); c != oadr2b.CodeOK {
		return fmt.Errorf("cancel registration: %s %s", c, msg)
	}
	v.mu.Lock()
	v.regID, v.quit = "", true
	v.requests = map[string]*request{}
	v.mu.Unlock()
	v.poke()
	return nil
}

// unregistered forgets the registration (rule 407: with its reports).
func (v *VEN) unregistered(ctx context.Context) {
	v.mu.Lock()
	v.regID = ""
	v.requests = map[string]*request{}
	v.mu.Unlock()
	if v.cfg.OnUnregistered != nil {
		v.cfg.OnUnregistered(ctx)
	}
	v.poke()
}

// poke wakes Run's loop.
func (v *VEN) poke() {
	select {
	case v.wake <- struct{}{}:
	default:
	}
}

// ---- polling and messages from the VTN ----------------------------------------

// Poll sends oadrPoll and handles what the VTN answers, until it has
// nothing more (at most 20 messages: rule 500 gives one per poll).
func (v *VEN) Poll(ctx context.Context) error {
	for range 20 {
		ans, err := v.Send(ctx, oadr2b.ServicePoll, oadr2b.SignedObject{Poll: &oadr2b.Poll{VenID: v.VenID()}})
		if err != nil {
			return err
		}
		if ans == nil {
			return nil
		}
		if ans.Response != nil {
			if ans.Response.EiResponse.ResponseCode == oadr2b.CodeNotRegistered {
				v.log.Info("OpenADR VEN: the VTN no longer knows this VEN")
				v.unregistered(ctx)
			}
			return nil
		}
		reply, after, err := v.onVTN(ctx, ans)
		if err != nil {
			return err
		}
		if reply != nil {
			if _, err := v.Send(ctx, serviceOf(reply), *reply); err != nil {
				return err
			}
		}
		if after != nil {
			if err := after(ctx); err != nil {
				return err
			}
		}
		if v.RegistrationID() == "" {
			return nil
		}
	}
	return nil
}

// serviceOf is the VTN endpoint of a VEN's message.
func serviceOf(so *oadr2b.SignedObject) string {
	switch {
	case so.CreatedEvent != nil, so.RequestEvent != nil:
		return oadr2b.ServiceEvent
	case so.RegisteredReport != nil, so.CreatedReport != nil, so.CanceledReport != nil, so.UpdatedReport != nil,
		so.RegisterReport != nil, so.UpdateReport != nil:
		return oadr2b.ServiceReport
	case so.CreateOpt != nil, so.CancelOpt != nil:
		return oadr2b.ServiceOpt
	}
	return oadr2b.ServiceRegisterParty
}

// onVTN handles a message the VTN started (from a poll or a push): reply
// is the VEN's answer (in the HTTP response when pushed, posted when
// polling) and after is what the VEN sends next.
func (v *VEN) onVTN(ctx context.Context, so *oadr2b.SignedObject) (reply *oadr2b.SignedObject, after func(context.Context) error, err error) {
	venID := v.VenID()
	if name := oadr2b.MessageName(so); name != "oadrCancelPartyRegistration" && v.RegistrationID() == "" {
		// Rule 405: payloads are ignored while not registered.
		return nil, nil, fmt.Errorf("%s received while not registered", name)
	}
	switch {
	case so.DistributeEvent != nil:
		resp := v.takeEvents(ctx, so.DistributeEvent)
		if resp == nil {
			return nil, nil, nil
		}
		return nil, func(ctx context.Context) error { return v.sendCreatedEvent(ctx, resp) }, nil
	case so.RegisterReport != nil:
		// The VTN's METADATA: this VEN asks for none of its reports.
		return &oadr2b.SignedObject{RegisteredReport: &oadr2b.RegisteredReport{EiResponse: ok(so.RegisterReport.RequestID), VenID: venID}}, nil, nil
	case so.CreateReport != nil:
		reply, after := v.acceptReports(so.CreateReport.RequestID, so.CreateReport.ReportRequests)
		return reply, after, nil
	case so.CancelReport != nil:
		reply, after := v.cancelReports(so.CancelReport)
		return reply, after, nil
	case so.UpdateReport != nil:
		return &oadr2b.SignedObject{UpdatedReport: &oadr2b.UpdatedReport{EiResponse: ok(so.UpdateReport.RequestID), VenID: venID}}, nil, nil
	case so.CancelPartyRegistration != nil:
		c := so.CancelPartyRegistration
		v.unregistered(ctx)
		return &oadr2b.SignedObject{CanceledPartyRegistration: &oadr2b.CanceledPartyRegistration{EiResponse: ok(c.RequestID),
			RegistrationID: c.RegistrationID, VenID: venID}}, nil, nil
	case so.RequestReregistration != nil:
		return &oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: ok(""), VenID: venID}}, v.Register, nil
	}
	return nil, nil, fmt.Errorf("the VTN sent %s", oadr2b.MessageName(so))
}

// ---- events -------------------------------------------------------------------

func (v *VEN) requestEvents(ctx context.Context) error {
	ans, err := v.Send(ctx, oadr2b.ServiceEvent, oadr2b.SignedObject{RequestEvent: &oadr2b.RequestEvent{
		EiRequestEvent: oadr2b.EiRequestEvent{RequestID: newID("re-"), VenID: v.VenID()}}})
	if err != nil {
		return fmt.Errorf("request event: %w", err)
	}
	if ans == nil || ans.DistributeEvent == nil {
		c, msg := codeOf(ans)
		return fmt.Errorf("request event: %s %s", c, msg)
	}
	if resp := v.takeEvents(ctx, ans.DistributeEvent); resp != nil {
		return v.sendCreatedEvent(ctx, resp)
	}
	return nil
}

func (v *VEN) sendCreatedEvent(ctx context.Context, resp *oadr2b.EiCreatedEvent) error {
	ans, err := v.Send(ctx, oadr2b.ServiceEvent, oadr2b.SignedObject{CreatedEvent: &oadr2b.CreatedEvent{EiCreatedEvent: *resp}})
	if err != nil {
		return err
	}
	if c, msg := codeOf(ans); ans != nil && c != oadr2b.CodeOK {
		return fmt.Errorf("the VTN answered oadrCreatedEvent with %s %s", c, msg)
	}
	return nil
}

// takeEvents replaces the event list (the distribution is complete,
// rules 56-62), asks OnEvent about new and modified events and builds the
// oadrCreatedEvent, nil when no event asks for an answer.
func (v *VEN) takeEvents(ctx context.Context, de *oadr2b.DistributeEvent) *oadr2b.EiCreatedEvent {
	v.mu.Lock()
	vtnID, venID := v.vtnID, v.venID
	v.mu.Unlock()
	if vtnID != "" && de.VtnID != "" && de.VtnID != vtnID {
		// Rule 21: an unexpected vtnID is an error for the whole payload.
		return &oadr2b.EiCreatedEvent{EiResponse: fail(oadr2b.CodeInvalidID, "vtnID "+de.VtnID+" is not this VEN's VTN", ""), VenID: venID}
	}
	type ask struct {
		e    *venEvent
		code string
	}
	var asks []ask
	v.mu.Lock()
	old := v.events
	v.events, v.order = map[string]*venEvent{}, nil
	for _, e := range de.Events {
		d := e.EiEvent.Descriptor
		prev := old[d.EventID]
		code := oadr2b.CodeOK
		ve := &venEvent{ev: e}
		switch {
		case prev != nil && d.ModificationNumber < prev.ev.EiEvent.Descriptor.ModificationNumber:
			// Rule 58: a lower modification number is out of sequence.
			code, ve = oadr2b.CodeOutOfSequence, prev
		case prev != nil && d.ModificationNumber == prev.ev.EiEvent.Descriptor.ModificationNumber:
			ve.opt = prev.opt
		}
		if _, dup := v.events[d.EventID]; !dup {
			v.order = append(v.order, d.EventID)
		}
		v.events[d.EventID] = ve
		asks = append(asks, ask{ve, code})
	}
	v.mu.Unlock()
	var rs []oadr2b.EventResponse
	for _, a := range asks {
		d := a.e.ev.EiEvent.Descriptor
		if a.code == oadr2b.CodeOK && a.e.opt == "" {
			opt := "optIn"
			if v.cfg.OnEvent != nil {
				if o := v.cfg.OnEvent(ctx, a.e.ev); o != "" {
					opt = o
				}
			}
			v.mu.Lock()
			a.e.opt = opt
			v.mu.Unlock()
		}
		if a.e.ev.ResponseRequired != "always" {
			continue
		}
		v.mu.Lock()
		opt := a.e.opt
		v.mu.Unlock()
		if a.code != oadr2b.CodeOK {
			opt = "optOut"
		}
		rs = append(rs, oadr2b.EventResponse{ResponseCode: a.code, ResponseDescription: "OK", RequestID: de.RequestID, OptType: opt,
			QualifiedEventID: oadr2b.QualifiedEventID{EventID: d.EventID, ModificationNumber: d.ModificationNumber}})
	}
	if len(rs) == 0 {
		return nil
	}
	// Rule 42: eiResponse's requestID stays empty when the payload has
	// eventResponses.
	return &oadr2b.EiCreatedEvent{EiResponse: ok(""), EventResponses: &oadr2b.EventResponses{Response: rs}, VenID: venID}
}

// ---- opts ---------------------------------------------------------------------

// CreateOpt sends an oadrCreateOpt; empty OptID, RequestID, VenID,
// CreatedDateTime and eiTarget are filled in. An opt for an event
// (QualifiedEventID) also becomes the VEN's answer to that event.
func (v *VEN) CreateOpt(ctx context.Context, opt oadr2b.CreateOpt) (optID string, err error) {
	venID := v.VenID()
	if opt.OptID == "" {
		opt.OptID = newID("opt-")
	}
	if opt.RequestID == "" {
		opt.RequestID = newID("o-")
	}
	if opt.VenID == "" {
		opt.VenID = venID
	}
	if opt.CreatedDateTime == "" {
		opt.CreatedDateTime = oadr2b.FormatTime(time.Now())
	}
	if opt.OptReason == "" {
		opt.OptReason = "participating"
	}
	if opt.Target.Empty() {
		opt.Target.VenID = []string{venID}
	}
	ans, err := v.Send(ctx, oadr2b.ServiceOpt, oadr2b.SignedObject{CreateOpt: &opt})
	if err != nil {
		return "", err
	}
	if c, msg := codeOf(ans); c != oadr2b.CodeOK || ans.CreatedOpt == nil {
		return "", fmt.Errorf("create opt: %s %s", c, msg)
	}
	eventID := ""
	if opt.QualifiedEventID != nil {
		eventID = opt.QualifiedEventID.EventID
	}
	v.mu.Lock()
	v.optIDs[opt.OptID] = eventID
	if e := v.events[eventID]; e != nil {
		e.opt = opt.OptType
	}
	v.mu.Unlock()
	return opt.OptID, nil
}

// OptEvent opts in to or out of an event the VEN has (oadrCreateOpt with
// its qualifiedEventID).
func (v *VEN) OptEvent(ctx context.Context, eventID, optType, reason string) (optID string, err error) {
	v.mu.Lock()
	e := v.events[eventID]
	var mod uint32
	if e != nil {
		mod = e.ev.EiEvent.Descriptor.ModificationNumber
	}
	v.mu.Unlock()
	if e == nil {
		return "", fmt.Errorf("no event %s", eventID)
	}
	return v.CreateOpt(ctx, oadr2b.CreateOpt{OptType: optType, OptReason: reason,
		MarketContext:    e.ev.EiEvent.Descriptor.MarketContext.MarketContext,
		QualifiedEventID: &oadr2b.QualifiedEventID{EventID: eventID, ModificationNumber: mod}})
}

// CancelOpt withdraws an opt (oadrCancelOpt).
func (v *VEN) CancelOpt(ctx context.Context, optID string) error {
	ans, err := v.Send(ctx, oadr2b.ServiceOpt, oadr2b.SignedObject{CancelOpt: &oadr2b.CancelOpt{RequestID: newID("co-"), OptID: optID, VenID: v.VenID()}})
	if err != nil {
		return err
	}
	if c, msg := codeOf(ans); c != oadr2b.CodeOK || ans.CanceledOpt == nil {
		return fmt.Errorf("cancel opt: %s %s", c, msg)
	}
	v.mu.Lock()
	delete(v.optIDs, optID)
	v.mu.Unlock()
	return nil
}

// ---- running ------------------------------------------------------------------

// Run registers, then polls (or serves pushes) and sends reports until
// ctx ends or the VEN cancels its registration. Failures are retried with
// a truncated binary exponential back-off with jitter (section 9.1.7).
// It returns nil when ctx ends, after its goroutines have stopped.
func (v *VEN) Run(ctx context.Context) error {
	v.mu.Lock()
	v.runCtx, v.quit = ctx, false
	v.mu.Unlock()
	if v.cfg.PushListen != "" {
		stop, err := v.startPush(ctx)
		if err != nil {
			return err
		}
		defer stop()
	}
	rctx, cancel := context.WithCancel(ctx)
	v.wg.Add(1)
	go func() { defer v.wg.Done(); v.reportLoop(rctx) }()
	defer func() { cancel(); v.wg.Wait() }()

	backoff := time.Second
	wait := func(d time.Duration) {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
		case <-v.wake:
		}
	}
	failed := func(what string, err error) {
		v.log.Warn("OpenADR VEN: "+what+" failed", "vtn", v.cfg.VTNURL, "error", err)
		wait(time.Duration(float64(backoff) * (0.9 + 0.2*mrand.Float64())))
		backoff = min(backoff*2, 5*time.Minute)
	}
	for ctx.Err() == nil {
		v.mu.Lock()
		quit, registered, push := v.quit, v.regID != "", v.pushURL != ""
		v.mu.Unlock()
		if quit {
			return nil
		}
		if !registered {
			if err := v.Register(ctx); err != nil {
				if ctx.Err() != nil {
					break
				}
				failed("registering with the VTN", err)
				continue
			}
			backoff = time.Second
		}
		if !push {
			if err := v.Poll(ctx); err != nil {
				if ctx.Err() != nil {
					break
				}
				failed("polling the VTN", err)
				continue
			}
		}
		backoff = time.Second
		if v.RegistrationID() == "" {
			// The VTN ended the registration: a pause before registering
			// again.
			wait(time.Second)
			continue
		}
		if push {
			wait(time.Hour)
		} else {
			wait(v.PollEvery())
		}
	}
	return nil
}

// startPush serves the push endpoints until the returned stop is called.
func (v *VEN) startPush(ctx context.Context) (func(), error) {
	ln, err := net.Listen("tcp", v.cfg.PushListen)
	if err != nil {
		return nil, fmt.Errorf("push listener: %w", err)
	}
	scheme := "http"
	tc := v.cfg.PushTLS
	if tc == nil && v.cfg.Certificate != nil {
		tc = &tls.Config{Certificates: []tls.Certificate{*v.cfg.Certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: v.cfg.RootCAs}
		if err := oadr2b.ApplyTLSProfile(tc, v.cfg.TLSProfile); err != nil {
			_ = ln.Close()
			return nil, err
		}
	}
	if tc != nil {
		ln = tls.NewListener(ln, tc)
		scheme = "https"
	}
	url := v.cfg.PushURL
	if url == "" {
		url = scheme + "://" + ln.Addr().String()
	}
	v.mu.Lock()
	v.pushURL = url
	v.mu.Unlock()
	srv := &http.Server{Handler: v.PushHandler(), ReadHeaderTimeout: 10 * time.Second}
	done := make(chan struct{})
	go func() { _ = srv.Serve(ln); close(done) }()
	return func() {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		_ = srv.Shutdown(sctx)
		cancel()
		<-done
	}, nil
}

// PushURL is the push endpoint's address once Run started it.
func (v *VEN) PushURL() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.pushURL
}

// PushHandler serves the VTN's pushes to …/OpenADR2/Simple/2.0b/<service>.
// Run serves it itself when PushListen is set; mount it elsewhere and set
// PushURL to register for push through another server.
func (v *VEN) PushHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, oadr2b.PathBase) {
			http.NotFound(w, r)
			return
		}
		body, okReq := oadr2b.ReadRequest(w, r)
		if !okReq {
			return
		}
		if v.cfg.Validate != nil {
			if err := v.cfg.Validate(body); err != nil {
				http.Error(w, err.Error(), http.StatusNotAcceptable)
				return
			}
		}
		so, err := oadr2b.Unmarshal(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotAcceptable)
			return
		}
		var reply *oadr2b.SignedObject
		if err := v.verify(body, r.TLS); err != nil {
			reply = &oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: fail(oadr2b.CodeBadSignature, err.Error(), ""), VenID: v.VenID()}}
		} else {
			var after func(context.Context) error
			reply, after, err = v.onVTN(r.Context(), so)
			if err != nil {
				reply = &oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: fail(oadr2b.CodeNotRegistered, err.Error(), ""), VenID: v.VenID()}}
			}
			if after != nil {
				v.mu.Lock()
				ctx := v.runCtx
				v.mu.Unlock()
				if ctx == nil {
					ctx = context.Background()
				}
				v.wg.Add(1)
				go func() {
					defer v.wg.Done()
					if err := after(ctx); err != nil && ctx.Err() == nil {
						v.log.Warn("OpenADR VEN: answering a pushed message failed", "error", err)
					}
				}()
			}
		}
		if reply == nil {
			reply = &oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: ok(""), VenID: v.VenID()}}
		}
		b, err := v.encode(*reply)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		oadr2b.WriteXML(w, r, b)
	})
}
