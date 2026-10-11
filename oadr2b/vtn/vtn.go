// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package vtn is a ready OpenADR 2.0b VTN for the simple-HTTP transport,
// as an http.Handler.
//
// It registers VENs (oadrQueryRegistration, oadrCreatePartyRegistration,
// oadrCancelPartyRegistration both ways, oadrRequestReregistration),
// queues messages for VENs that poll (oadrPoll) and posts them to VENs
// that registered for push, distributes events with modification numbers
// and cancellation, takes oadrCreatedEvent, oadrCreateOpt and
// oadrCancelOpt, and runs the report exchange (oadrRegisterReport,
// oadrCreateReport, oadrUpdateReport, oadrCancelReport). Payloads can be
// signed and signatures required, with replay protection; behind TLS the
// VEN's client certificate fingerprint identifies it.
//
// What the VTN decides is left to callbacks in Config: who may register
// and under which venID, which reports to request, what to do with report
// data and with the VENs' answers to events. Registrations are kept in a
// Store (in memory by default); events, queued messages and report
// requests are kept in memory. One VTN serves any number of VENs and is
// safe for concurrent use.
//
// Clause references are to the OpenADR 2.0b profile specification and its
// conformance rules.
package vtn

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// Config configures a VTN. Every callback is optional.
type Config struct {
	// VtnID is the VTN's vtnID (default "vtn").
	VtnID string
	// PollFreq is the poll frequency asked of VENs (default 10 s, whole
	// seconds, at least one).
	PollFreq time.Duration
	// Signer, when set, signs every answer and push.
	Signer *oadr2b.Signer
	// RequireSignatures refuses VEN payloads that are not signed, are
	// replayed, or are signed by another certificate than the VEN's TLS
	// client certificate (or, without TLS, the certificate it registered
	// with). Refusals are oadrResponse with oadr2b.CodeBadSignature.
	RequireSignatures bool
	// Guard is the replay guard used with RequireSignatures (default: a
	// guard with a five-minute window).
	Guard *oadr2b.ReplayGuard
	// PushClient posts to push-mode VENs (default: a client with a 10 s
	// timeout). Give it a client certificate for mutual TLS.
	PushClient *http.Client
	// PushRetry is the first wait after a failed push; it doubles up to
	// five minutes (default 2 s).
	PushRetry time.Duration
	// Store keeps registrations (default NewMemoryStore()).
	Store Store
	// Validate, when set, checks every payload received (a schema check
	// such as oadr2b.SchemaSet.Check); a failure is answered with HTTP 406.
	Validate func([]byte) error
	// Metadata is the VTN's own METADATA report list, sent when a VEN asks
	// for it, and after every new registration when SendMetadata is set
	// (rule 301; most VENs accept it, some ignore it).
	Metadata     []oadr2b.Report
	SendMetadata bool
	// Logger receives warnings (default: discarded).
	Logger *slog.Logger

	// OnCreatePartyRegistration decides a new registration: it returns the
	// venID and registrationID to give the VEN ("" for each picks the
	// VEN's own venID or a new one, and a new registrationID), or an
	// error to refuse (Refuse gives the response code). Without it every
	// VEN may register.
	OnCreatePartyRegistration func(ctx context.Context, info RegistrationInfo) (venID, registrationID string, err error)
	// OnCancelPartyRegistration is told of a registration that ended,
	// cancelled by the VEN or by CancelRegistration.
	OnCancelPartyRegistration func(ctx context.Context, r Registration)
	// OnRegisterReport receives a VEN's METADATA and returns the report
	// requests to send in oadrRegisteredReport (nil: none; see RequestAll).
	OnRegisterReport func(ctx context.Context, venID string, reports []oadr2b.Report) []oadr2b.ReportRequest
	// OnCreatedReport is told that a VEN accepted report requests; pending
	// lists its periodic ones.
	OnCreatedReport func(ctx context.Context, venID string, pending []string)
	// OnUpdateReport receives report data for requests that are active;
	// an error is answered with its code (Refuse) or 454.
	OnUpdateReport func(ctx context.Context, venID string, reports []oadr2b.Report) error
	// OnEventResponse receives a VEN's answer to one event from
	// oadrCreatedEvent: optIn or optOut (an answer with a response code
	// other than 200 counts as optOut).
	OnEventResponse func(ctx context.Context, venID, eventID, optType string)
	// OnCreateOpt receives an oadrCreateOpt (for an event or an
	// availability schedule); an error refuses it.
	OnCreateOpt func(ctx context.Context, venID string, opt *oadr2b.CreateOpt) error
	// OnCancelOpt receives an oadrCancelOpt of a known optID.
	OnCancelOpt func(ctx context.Context, venID, optID string) error
	// OnPushError is told of each failed push (it is retried).
	OnPushError func(venID string, err error)
}

// RegistrationInfo is what a VEN asks for in oadrCreatePartyRegistration.
type RegistrationInfo struct {
	VenID            string // the venID the VEN sent, if any
	VenName          string
	Fingerprint      string // TLS client certificate, or signer when there is no TLS
	ProfileName      string
	TransportName    string
	TransportAddress string
	HTTPPullModel    bool
	ReportOnly       bool
	XMLSignature     bool
	// Existing is the current registration of this certificate or venID.
	Existing *Registration
}

// Refusal is an error that carries an OpenADR response code.
type Refusal struct{ Code, Description string }

func (r *Refusal) Error() string { return r.Code + " " + r.Description }

// Refuse returns a Refusal; callbacks return it to choose the code.
func Refuse(code, description string) error { return &Refusal{Code: code, Description: description} }

func refusal(err error, def string) (string, string) {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code, r.Description
	}
	return def, err.Error()
}

// VTN is an OpenADR 2.0b VTN. Create it with New.
type VTN struct {
	cfg    Config
	log    *slog.Logger
	guard  *oadr2b.ReplayGuard
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	states map[string]*venState // by venID
	fps    map[string]string    // fingerprint → venID
	closed bool
}

// venState is what the VTN holds for one VEN.
type venState struct {
	reg         *Registration // nil when not registered
	queue       []oadr2b.SignedObject
	events      map[string]*evState
	order       []string
	eventsDirty bool
	eventsGen   uint64
	meta        []oadr2b.Report
	requests    map[string]string // active reportRequestID → reportSpecifierID
	final       map[string]bool   // cancelled with reportToFollow: one more report
	cancelled   map[string]bool
	opts        map[string]string // optID → eventID ("" for a schedule)
	pushing     bool
	pushFails   int
	pushTimer   *time.Timer
}

func newState() *venState {
	st := &venState{events: map[string]*evState{}}
	st.forget()
	return st
}

// forget drops what a registration built up: queued messages, METADATA,
// report requests and opts (rules 406 and 407). Events stay.
func (st *venState) forget() {
	st.queue, st.meta = nil, nil
	st.requests, st.final, st.cancelled = map[string]string{}, map[string]bool{}, map[string]bool{}
	st.opts = map[string]string{}
	st.pushFails = 0
	if st.pushTimer != nil {
		st.pushTimer.Stop()
		st.pushTimer = nil
	}
}

// New creates a VTN. Close it to stop pushes in progress.
func New(cfg Config) *VTN {
	if cfg.VtnID == "" {
		cfg.VtnID = "vtn"
	}
	if cfg.PollFreq <= 0 {
		cfg.PollFreq = 10 * time.Second
	}
	// Durations are sent in whole seconds (rule 1).
	cfg.PollFreq = max(cfg.PollFreq.Truncate(time.Second), time.Second)
	if cfg.Store == nil {
		cfg.Store = NewMemoryStore()
	}
	if cfg.PushClient == nil {
		cfg.PushClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.PushRetry <= 0 {
		cfg.PushRetry = 2 * time.Second
	}
	v := &VTN{cfg: cfg, log: cfg.Logger, guard: cfg.Guard, states: map[string]*venState{}, fps: map[string]string{}}
	if v.log == nil {
		v.log = slog.New(slog.DiscardHandler)
	}
	if v.guard == nil {
		v.guard = &oadr2b.ReplayGuard{}
	}
	v.ctx, v.cancel = context.WithCancel(context.Background())
	return v
}

// Close stops pushes and retries; requests still answer.
func (v *VTN) Close() {
	v.mu.Lock()
	v.closed = true
	for _, st := range v.states {
		if st.pushTimer != nil {
			st.pushTimer.Stop()
		}
	}
	v.mu.Unlock()
	v.cancel()
	v.wg.Wait()
}

func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// ---- lookups ----------------------------------------------------------------

// stateLocked returns venID's state, creating it; v.mu held.
func (v *VTN) stateLocked(venID string) *venState {
	st := v.states[venID]
	if st == nil {
		st = newState()
		v.states[venID] = st
	}
	return st
}

// cache records a registration loaded from or written to the store.
func (v *VTN) cache(r *Registration) {
	v.mu.Lock()
	defer v.mu.Unlock()
	st := v.stateLocked(r.VenID)
	if st.reg != nil && st.reg.Fingerprint != "" {
		delete(v.fps, strings.ToUpper(st.reg.Fingerprint))
	}
	c := *r
	st.reg = &c
	if r.Fingerprint != "" {
		v.fps[strings.ToUpper(r.Fingerprint)] = r.VenID
	}
}

// lookup is venID's registration, or nil.
func (v *VTN) lookup(ctx context.Context, venID string) *Registration {
	if venID == "" {
		return nil
	}
	v.mu.Lock()
	if st := v.states[venID]; st != nil && st.reg != nil {
		r := *st.reg
		v.mu.Unlock()
		return &r
	}
	v.mu.Unlock()
	r, err := v.cfg.Store.Get(ctx, venID)
	if err != nil {
		v.log.Warn("OpenADR VTN: reading a registration", "ven", venID, "error", err)
		return nil
	}
	if r != nil {
		v.cache(r)
	}
	return r
}

// lookupFP is the registration of a certificate fingerprint, or nil.
func (v *VTN) lookupFP(ctx context.Context, fp string) *Registration {
	v.mu.Lock()
	if id, ok := v.fps[strings.ToUpper(fp)]; ok {
		if st := v.states[id]; st != nil && st.reg != nil {
			r := *st.reg
			v.mu.Unlock()
			return &r
		}
	}
	v.mu.Unlock()
	r, err := v.cfg.Store.ByFingerprint(ctx, fp)
	if err != nil {
		v.log.Warn("OpenADR VTN: reading a registration", "fingerprint", fp, "error", err)
		return nil
	}
	if r != nil {
		v.cache(r)
	}
	return r
}

// Registration is venID's registration, or nil.
func (v *VTN) Registration(ctx context.Context, venID string) (*Registration, error) {
	if r := v.lookup(ctx, venID); r != nil {
		return r, nil
	}
	return v.cfg.Store.Get(ctx, venID)
}

// Registrations lists every registration in the store.
func (v *VTN) Registrations(ctx context.Context) ([]Registration, error) {
	return v.cfg.Store.List(ctx)
}

// ---- HTTP -------------------------------------------------------------------

// services maps each message a VEN sends to its endpoint.
var services = map[string]string{
	"oadrQueryRegistration":         oadr2b.ServiceRegisterParty,
	"oadrCreatePartyRegistration":   oadr2b.ServiceRegisterParty,
	"oadrCancelPartyRegistration":   oadr2b.ServiceRegisterParty,
	"oadrCanceledPartyRegistration": oadr2b.ServiceRegisterParty,
	"oadrRequestEvent":              oadr2b.ServiceEvent,
	"oadrCreatedEvent":              oadr2b.ServiceEvent,
	"oadrRegisterReport":            oadr2b.ServiceReport,
	"oadrRegisteredReport":          oadr2b.ServiceReport,
	"oadrCreateReport":              oadr2b.ServiceReport,
	"oadrCreatedReport":             oadr2b.ServiceReport,
	"oadrUpdateReport":              oadr2b.ServiceReport,
	"oadrUpdatedReport":             oadr2b.ServiceReport,
	"oadrCancelReport":              oadr2b.ServiceReport,
	"oadrCanceledReport":            oadr2b.ServiceReport,
	"oadrCreateOpt":                 oadr2b.ServiceOpt,
	"oadrCancelOpt":                 oadr2b.ServiceOpt,
	"oadrPoll":                      oadr2b.ServicePoll,
}

// ServeHTTP answers simple-HTTP requests to …/OpenADR2/Simple/2.0b/<service>
// under any prefix (section 9.1).
func (v *VTN) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i := strings.Index(r.URL.Path, oadr2b.PathBase)
	if i < 0 {
		http.NotFound(w, r)
		return
	}
	svc := strings.Trim(r.URL.Path[i+len(oadr2b.PathBase):], "/")
	switch svc {
	case oadr2b.ServiceRegisterParty, oadr2b.ServiceEvent, oadr2b.ServiceReport, oadr2b.ServiceOpt, oadr2b.ServicePoll:
	default:
		http.NotFound(w, r)
		return
	}
	body, ok := oadr2b.ReadRequest(w, r)
	if !ok {
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
	fp := ""
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		fp = oadr2b.Fingerprint(r.TLS.PeerCertificates[0].Raw)
	}
	out := v.handle(r.Context(), svc, fp, body, so)
	b, err := v.encode(*out)
	if err != nil {
		v.log.Error("OpenADR VTN: answer not written", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	oadr2b.WriteXML(w, r, b)
}

// encode marshals and, with a Signer, signs a message.
func (v *VTN) encode(so oadr2b.SignedObject) ([]byte, error) {
	b, err := oadr2b.Marshal(so)
	if err != nil || v.cfg.Signer == nil {
		return b, err
	}
	return v.cfg.Signer.Sign(b)
}

// checkSignature applies RequireSignatures and returns the signer's
// fingerprint.
func (v *VTN) checkSignature(body []byte, tlsFP string, reg *Registration) (string, error) {
	got, err := oadr2b.VerifyPayload(body)
	if err != nil {
		return "", err
	}
	fp := oadr2b.Fingerprint(got.Cert.Raw)
	switch {
	case tlsFP != "" && fp != tlsFP:
		return "", fmt.Errorf("signed by %s, the TLS client certificate is %s", fp, tlsFP)
	case tlsFP == "" && reg != nil && reg.Fingerprint != "" && !strings.EqualFold(fp, reg.Fingerprint):
		return "", fmt.Errorf("signed by %s, the VEN registered with %s", fp, reg.Fingerprint)
	}
	return fp, v.guard.Check(got)
}

func response(code, desc, requestID, venID string) *oadr2b.SignedObject {
	return &oadr2b.SignedObject{Response: &oadr2b.Response{EiResponse: oadr2b.EiResponse{ResponseCode: code, ResponseDescription: desc, RequestID: requestID}, VenID: venID}}
}

func ok(requestID string) oadr2b.EiResponse {
	return oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, ResponseDescription: "OK", RequestID: requestID}
}

func fail(code, desc, requestID string) oadr2b.EiResponse {
	return oadr2b.EiResponse{ResponseCode: code, ResponseDescription: desc, RequestID: requestID}
}

// handle answers one message; fp is the TLS client certificate's
// fingerprint ("" without one).
func (v *VTN) handle(ctx context.Context, svc, fp string, body []byte, so *oadr2b.SignedObject) *oadr2b.SignedObject {
	name := oadr2b.MessageName(so)
	if want, known := services[name]; (known && want != svc) || (!known && name != "oadrResponse") {
		return response(oadr2b.CodeInvalidData, name+" is not a message a VEN sends to "+svc, requestIDOf(so), "")
	}
	claimed := messageVenID(so)
	var reg *Registration
	if fp != "" {
		reg = v.lookupFP(ctx, fp)
	}
	if reg == nil && claimed != "" {
		if r := v.lookup(ctx, claimed); r != nil && (fp == "" || r.Fingerprint == "" || strings.EqualFold(r.Fingerprint, fp)) {
			reg = r
		}
	}
	// Rules 500 and 517: a venID other than the sender's is 452.
	if reg != nil && claimed != "" && claimed != reg.VenID {
		return response(oadr2b.CodeInvalidID, "venID "+claimed+" does not belong to this client", requestIDOf(so), reg.VenID)
	}
	signer := ""
	if v.cfg.RequireSignatures {
		var err error
		if signer, err = v.checkSignature(body, fp, reg); err != nil {
			v.log.Warn("OpenADR VTN: message refused: XML signature", "ven", claimed, "error", err)
			return response(oadr2b.CodeBadSignature, "XML signature: "+err.Error(), requestIDOf(so), claimed)
		}
	}
	switch {
	case so.QueryRegistration != nil:
		return v.created(reg, so.QueryRegistration.RequestID)
	case so.CreatePartyRegistration != nil:
		return v.register(ctx, reg, fp, signer, so.CreatePartyRegistration)
	case so.CancelPartyRegistration != nil:
		return v.cancelRegistration(ctx, reg, so.CancelPartyRegistration)
	case so.CanceledPartyRegistration != nil:
		return response(oadr2b.CodeOK, "OK", so.CanceledPartyRegistration.EiResponse.RequestID, claimed)
	case so.Response != nil:
		return response(oadr2b.CodeOK, "OK", "", claimed)
	}
	if reg == nil {
		// Rule 517: registered VENs only.
		return response(oadr2b.CodeNotRegistered, "the VEN is not registered", requestIDOf(so), claimed)
	}
	venID := reg.VenID
	switch {
	case so.Poll != nil:
		return v.poll(ctx, venID)
	case so.RequestEvent != nil:
		rq := so.RequestEvent.EiRequestEvent
		v.mu.Lock()
		st := v.stateLocked(venID)
		st.eventsDirty = false
		de := v.distributionLocked(venID, st, rq.RequestID, rq.ReplyLimit, time.Now())
		v.mu.Unlock()
		return &oadr2b.SignedObject{DistributeEvent: de}
	case so.CreatedEvent != nil:
		c, desc := v.createdEvent(ctx, venID, so.CreatedEvent)
		return response(c, desc, so.CreatedEvent.EiCreatedEvent.EiResponse.RequestID, venID)
	case so.RegisterReport != nil:
		return v.registerReport(ctx, venID, so.RegisterReport)
	case so.RegisteredReport != nil:
		return response(oadr2b.CodeOK, "OK", so.RegisteredReport.EiResponse.RequestID, venID)
	case so.CreateReport != nil:
		return v.venCreateReport(venID, so.CreateReport)
	case so.CreatedReport != nil:
		if v.cfg.OnCreatedReport != nil {
			v.cfg.OnCreatedReport(ctx, venID, so.CreatedReport.PendingReports.ReportRequestID)
		}
		return response(oadr2b.CodeOK, "OK", so.CreatedReport.EiResponse.RequestID, venID)
	case so.CancelReport != nil:
		return v.venCancelReport(venID, so.CancelReport)
	case so.CanceledReport != nil:
		return response(oadr2b.CodeOK, "OK", so.CanceledReport.EiResponse.RequestID, venID)
	case so.UpdateReport != nil:
		return v.updateReport(ctx, venID, so.UpdateReport)
	case so.UpdatedReport != nil:
		return response(oadr2b.CodeOK, "OK", so.UpdatedReport.EiResponse.RequestID, venID)
	case so.CreateOpt != nil:
		return v.createOpt(ctx, venID, so.CreateOpt)
	case so.CancelOpt != nil:
		return v.cancelOpt(ctx, venID, so.CancelOpt)
	}
	return response(oadr2b.CodeInvalidData, "unexpected message", "", venID)
}

// requestIDOf is the message's top-level requestID, if it has one.
func requestIDOf(so *oadr2b.SignedObject) string {
	v := reflect.ValueOf(so).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		if f.Kind() != reflect.Pointer || f.IsNil() {
			continue
		}
		if r := f.Elem().FieldByName("RequestID"); r.IsValid() && r.Kind() == reflect.String {
			return r.String()
		}
	}
	return ""
}

// messageVenID is the venID a message names, or "".
func messageVenID(so *oadr2b.SignedObject) string {
	switch {
	case so.CreatePartyRegistration != nil:
		return so.CreatePartyRegistration.VenID
	case so.CancelPartyRegistration != nil:
		return so.CancelPartyRegistration.VenID
	case so.CanceledPartyRegistration != nil:
		return so.CanceledPartyRegistration.VenID
	case so.Response != nil:
		return so.Response.VenID
	case so.Poll != nil:
		return so.Poll.VenID
	case so.RequestEvent != nil:
		return so.RequestEvent.EiRequestEvent.VenID
	case so.CreatedEvent != nil:
		return so.CreatedEvent.EiCreatedEvent.VenID
	case so.RegisterReport != nil:
		return so.RegisterReport.VenID
	case so.RegisteredReport != nil:
		return so.RegisteredReport.VenID
	case so.CreateReport != nil:
		return so.CreateReport.VenID
	case so.CreatedReport != nil:
		return so.CreatedReport.VenID
	case so.UpdateReport != nil:
		return so.UpdateReport.VenID
	case so.UpdatedReport != nil:
		return so.UpdatedReport.VenID
	case so.CancelReport != nil:
		return so.CancelReport.VenID
	case so.CanceledReport != nil:
		return so.CanceledReport.VenID
	case so.CreateOpt != nil:
		return so.CreateOpt.VenID
	case so.CancelOpt != nil:
		return so.CancelOpt.VenID
	}
	return ""
}

// ---- EiRegisterParty --------------------------------------------------------

func profiles() oadr2b.Profiles {
	return oadr2b.Profiles{Profile: []oadr2b.Profile{{Name: oadr2b.Profile20b,
		Transports: oadr2b.Transports{Transport: []oadr2b.Transport{{Name: oadr2b.TransportName}}}}}}
}

// created answers a query: the registration IDs only when the sender is
// registered (rule 404).
func (v *VTN) created(reg *Registration, requestID string) *oadr2b.SignedObject {
	c := &oadr2b.CreatedPartyRegistration{EiResponse: ok(requestID), VtnID: v.cfg.VtnID, Profiles: profiles(),
		PollFreq: &oadr2b.DurationProp{Duration: oadr2b.FormatDuration(v.cfg.PollFreq)}}
	if reg != nil {
		c.RegistrationID, c.VenID = reg.RegistrationID, reg.VenID
	}
	return &oadr2b.SignedObject{CreatedPartyRegistration: c}
}

func (v *VTN) register(ctx context.Context, reg *Registration, fp, signer string, c *oadr2b.CreatePartyRegistration) *oadr2b.SignedObject {
	failed := func(code, msg string) *oadr2b.SignedObject {
		return &oadr2b.SignedObject{CreatedPartyRegistration: &oadr2b.CreatedPartyRegistration{
			EiResponse: fail(code, msg, c.RequestID), VtnID: v.cfg.VtnID, Profiles: profiles()}}
	}
	if c.ProfileName != "" && !strings.HasPrefix(strings.ToLower(c.ProfileName), "2.0b") {
		return failed(oadr2b.CodeInvalidData, "this VTN offers profile 2.0b")
	}
	if c.TransportName != "" && !strings.EqualFold(c.TransportName, oadr2b.TransportName) {
		return failed(oadr2b.CodeInvalidData, "this VTN offers transport simpleHttp")
	}
	// Rule 402: a missing oadrHttpPullModel is read as pull.
	push := c.HTTPPullModel != nil && !*c.HTTPPullModel
	if push && c.TransportAddress == "" {
		return failed(oadr2b.CodeInvalidData, "push mode needs an oadrTransportAddress")
	}
	if fp == "" {
		fp = signer
	}
	now := time.Now()
	nr := Registration{VenName: c.VenName, Fingerprint: fp, ProfileName: c.ProfileName, TransportName: c.TransportName,
		TransportAddress: c.TransportAddress, Push: push, ReportOnly: c.ReportOnly, XMLSignature: c.XMLSignature, Registered: now}
	if nr.ProfileName == "" {
		nr.ProfileName = oadr2b.Profile20b
	}
	if nr.TransportName == "" {
		nr.TransportName = oadr2b.TransportName
	}
	if !push {
		nr.TransportAddress = ""
	}
	fresh := c.RegistrationID == ""
	if !fresh {
		// Rule 400: an unknown registrationID is 452.
		if reg == nil || reg.RegistrationID != c.RegistrationID {
			return failed(oadr2b.CodeInvalidID, "unknown registrationID")
		}
		nr.VenID, nr.RegistrationID = reg.VenID, reg.RegistrationID
		if nr.Fingerprint == "" {
			nr.Fingerprint = reg.Fingerprint
		}
	} else {
		existing := reg
		if existing == nil && c.VenID != "" {
			existing = v.lookup(ctx, c.VenID)
		}
		info := RegistrationInfo{VenID: c.VenID, VenName: c.VenName, Fingerprint: fp, ProfileName: nr.ProfileName, TransportName: nr.TransportName,
			TransportAddress: c.TransportAddress, HTTPPullModel: !push, ReportOnly: c.ReportOnly, XMLSignature: c.XMLSignature, Existing: existing}
		venID, regID := "", ""
		if v.cfg.OnCreatePartyRegistration != nil {
			var err error
			if venID, regID, err = v.cfg.OnCreatePartyRegistration(ctx, info); err != nil {
				code, desc := refusal(err, oadr2b.CodeNotAllowed)
				return failed(code, desc)
			}
		}
		switch {
		case venID != "":
		case c.VenID != "":
			venID = c.VenID
		case reg != nil:
			venID = reg.VenID
		default:
			venID = newID("ven-")
		}
		if other := v.lookup(ctx, venID); other != nil && other.Fingerprint != "" && fp != "" && !strings.EqualFold(other.Fingerprint, fp) {
			return failed(oadr2b.CodeInvalidID, "venID "+venID+" is registered with another certificate")
		}
		if regID == "" {
			// Rule 406: a new registration of a registered VEN starts
			// over; its registrationID is kept.
			if old := v.lookup(ctx, venID); old != nil {
				regID = old.RegistrationID
			} else {
				regID = newID("reg-")
			}
		}
		nr.VenID, nr.RegistrationID = venID, regID
		if reg != nil && reg.VenID != venID {
			// The certificate moves to another venID: the old one ends.
			v.unregister(ctx, *reg, false)
		}
	}
	if err := v.cfg.Store.Put(ctx, nr); err != nil {
		v.log.Error("OpenADR VTN: storing a registration", "ven", nr.VenID, "error", err)
		return failed(oadr2b.CodeDeploymentErr, "the VTN could not store the registration")
	}
	v.cache(&nr)
	v.mu.Lock()
	st := v.stateLocked(nr.VenID)
	if fresh {
		st.forget()
		if v.cfg.SendMetadata {
			// Rule 301: the VTN's METADATA after a registration.
			st.queue = append(st.queue, oadr2b.SignedObject{RegisterReport: &oadr2b.RegisterReport{RequestID: newID("req-"),
				Reports: v.cfg.Metadata, VenID: nr.VenID}})
		}
	}
	st.eventsDirty = v.hasEventsLocked(nr.VenID, st, now)
	v.mu.Unlock()
	if push {
		v.kick(nr.VenID)
	}
	out := v.created(&nr, c.RequestID)
	return out
}

func (v *VTN) cancelRegistration(ctx context.Context, reg *Registration, c *oadr2b.CancelPartyRegistration) *oadr2b.SignedObject {
	if reg == nil || reg.RegistrationID != c.RegistrationID {
		return &oadr2b.SignedObject{CanceledPartyRegistration: &oadr2b.CanceledPartyRegistration{
			EiResponse: fail(oadr2b.CodeInvalidID, "unknown registrationID", c.RequestID), RegistrationID: c.RegistrationID, VenID: c.VenID}}
	}
	v.unregister(ctx, *reg, true)
	return &oadr2b.SignedObject{CanceledPartyRegistration: &oadr2b.CanceledPartyRegistration{EiResponse: ok(c.RequestID),
		RegistrationID: c.RegistrationID, VenID: reg.VenID}}
}

// unregister ends a registration and erases its data (rule 407).
func (v *VTN) unregister(ctx context.Context, reg Registration, tell bool) {
	if err := v.cfg.Store.Delete(ctx, reg.VenID); err != nil {
		v.log.Warn("OpenADR VTN: deleting a registration", "ven", reg.VenID, "error", err)
	}
	v.mu.Lock()
	if st := v.states[reg.VenID]; st != nil {
		st.reg = nil
		st.eventsDirty = false
		st.forget()
	}
	for fp, id := range v.fps {
		if id == reg.VenID {
			delete(v.fps, fp)
		}
	}
	v.mu.Unlock()
	if tell && v.cfg.OnCancelPartyRegistration != nil {
		v.cfg.OnCancelPartyRegistration(ctx, reg)
	}
}

// registered returns venID's registration or an error.
func (v *VTN) registered(venID string) (*Registration, error) {
	r := v.lookup(v.ctx, venID)
	if r == nil {
		return nil, fmt.Errorf("VEN %s is not registered", venID)
	}
	return r, nil
}

// enqueue adds a message for venID's next poll, or pushes it.
func (v *VTN) enqueue(venID string, so oadr2b.SignedObject) error {
	r, err := v.registered(venID)
	if err != nil {
		return err
	}
	v.mu.Lock()
	st := v.stateLocked(venID)
	st.queue = append(st.queue, so)
	v.mu.Unlock()
	if r.Push {
		v.kick(venID)
	}
	return nil
}

// Reregister asks the VEN to register again (oadrRequestReregistration).
func (v *VTN) Reregister(venID string) error {
	return v.enqueue(venID, oadr2b.SignedObject{RequestReregistration: &oadr2b.RequestReregistration{VenID: venID}})
}

// CancelRegistration ends the VEN's registration with
// oadrCancelPartyRegistration; it ends when the message is delivered.
func (v *VTN) CancelRegistration(venID string) error {
	r, err := v.registered(venID)
	if err != nil {
		return err
	}
	return v.enqueue(venID, oadr2b.SignedObject{CancelPartyRegistration: &oadr2b.CancelPartyRegistration{
		RequestID: newID("req-"), RegistrationID: r.RegistrationID, VenID: venID}})
}

// ---- OadrPoll ---------------------------------------------------------------

// poll answers with the next waiting message (rule 500: one per poll),
// else the event list if it changed, else an oadrResponse.
func (v *VTN) poll(ctx context.Context, venID string) *oadr2b.SignedObject {
	v.mu.Lock()
	st := v.stateLocked(venID)
	var out *oadr2b.SignedObject
	switch {
	case len(st.queue) > 0:
		m := st.queue[0]
		st.queue = st.queue[1:]
		out = &m
	case st.eventsDirty:
		st.eventsDirty = false
		out = &oadr2b.SignedObject{DistributeEvent: v.distributionLocked(venID, st, newID("req-"), 0, time.Now())}
	}
	var reg *Registration
	if out != nil && out.CancelPartyRegistration != nil && st.reg != nil {
		r := *st.reg
		reg = &r
	}
	v.mu.Unlock()
	if reg != nil {
		v.unregister(ctx, *reg, true)
	}
	if out == nil {
		out = response(oadr2b.CodeOK, "OK", "", venID)
	}
	return out
}
