// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package vtn is an OpenADR 3 Virtual Top Node: the REST API of OpenADR
// 3.1 (and 3.0 with Config.Version) as an http.Handler on net/http.
//
// It serves programs, events, reports, subscriptions, vens and resources
// with the object checks of package oadr3; an OAuth2 client-credentials
// token endpoint and token discovery (GET /auth/server); the scopes of
// business-logic (BL) and VEN clients; object privacy between VENs
// (targets for programs and events, the owning client for the other
// types); filtering and paging; problem answers; subscriptions with
// webhook delivery (echo check, bearer token, ordered per callback,
// retries with back-off, broken-callback detection, an optional HMAC
// signature) and an optional MQTT notifier on a broker you supply.
//
// Objects are kept in a Store: NewMemoryStore by default, or your own
// (a database, say). Business logic may run in the same process through
// Create, Update, Delete, Get and List, and learn of every change through
// Config.OnChange.
//
// The OpenADR 3 definitions (the OpenAPI YAML, the Definition and the
// User Guide) were read as reference; none of their text is here. Set
// Config.Validator to check every request and answer against your own
// copy of the YAML.
package vtn

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/openadr/oadr3"
)

// Object is one object's JSON representation.
type Object = oadr3.Object

// Versions of the API (Config.Version).
const (
	Version31 = "3.1"
	Version30 = "3.0"
)

// Orders of event searches (Config.EventOrder).
const (
	EventsOldestFirst = "created"
	EventsByPriority  = "priority"
)

// Roles of OAuth2 clients.
const (
	RoleBL  = "BL"
	RoleVEN = "VEN"
)

// InternalClientID is the client ID of changes made through the VTN's own
// methods (Create, Update, Delete): business logic in the same process.
const InternalClientID = "vtn-internal-bl"

// Client is an OAuth2 client allowed to obtain tokens.
type Client struct {
	ClientID string
	Secret   string
	// Role is RoleBL or RoleVEN.
	Role string
	// Scopes limits the client below its role's scopes (nil: all of them).
	Scopes []string
}

// Config configures a VTN. The zero value of every field is usable except
// that a VTN needs Clients, an Authenticator or AnonymousRead.
type Config struct {
	// BasePath is the path before /programs, /events, … ("" serves them at
	// the root), e.g. "/openadr3/3.1.0".
	BasePath string
	// PublicURL is how clients reach the VTN, up to BasePath; it makes the
	// token URL announced by GET /auth/server. Without it the URL is built
	// from the request's Host (and TLS state).
	PublicURL string
	// Version is Version31 (default) or Version30.
	Version string
	// Clients may obtain tokens from the VTN's token endpoint.
	Clients []Client
	// TokenKey signs the VTN's tokens (HS256, at least 32 bytes). Without
	// it a random key is made: tokens then do not survive a restart, and
	// clients fetch a new one after a 401.
	TokenKey []byte
	// TokenLifetime of issued tokens (default 1 h).
	TokenLifetime time.Duration
	// TokenURL announces an external authorisation server instead of the
	// VTN's own token endpoint (which then answers 501).
	TokenURL string
	// Authenticator checks bearer tokens the VTN did not issue (an
	// external authorisation server's, say). It is asked only when a token
	// is not one of the VTN's own.
	Authenticator Authenticator
	// EventOrder is the order of event searches: EventsOldestFirst (the
	// default, stable for paging) or EventsByPriority (the order
	// openleadr-rs uses). The definition leaves it to the VTN.
	EventOrder string
	// AnonymousRead answers GET of programs and events without a token
	// (untargeted ones only), e.g. for public tariffs.
	AnonymousRead bool
	// Store keeps the objects (default NewMemoryStore()).
	Store Store
	// Webhooks configures notification delivery to callback URLs.
	Webhooks WebhookConfig
	// MQTT, when set, publishes notifications through a broker.
	MQTT *MQTTConfig
	// Validator checks requests and answers against the OpenAPI
	// definition; a request that fails is answered 400, an answer that
	// fails is replaced by a 500 problem.
	Validator oadr3.Validator
	// OnChange is called after every committed change, in order, outside
	// the VTN's locks.
	OnChange func(Change)
	// OnDeliveryError is called when a notification could not be
	// delivered after its retries.
	OnDeliveryError func(Delivery, error)
	// Logger receives warnings (default: discarded).
	Logger *slog.Logger
	// Now is the clock (default time.Now), for tests.
	Now func() time.Time
}

// Change is one committed change.
type Change struct {
	// Operation is CREATE, UPDATE or DELETE.
	Operation  string
	ObjectType string
	Object     Object
	// ClientID is the client that made the change (InternalClientID for
	// the VTN's own methods).
	ClientID string
}

// VTN is an OpenADR 3 VTN. It is an http.Handler; create it with New and
// Close it when done.
type VTN struct {
	cfg     Config
	clients map[string]*Client
	key     []byte
	store   Store
	mux     *http.ServeMux
	log     *slog.Logger
	hooks   *deliverer

	// wmu serialises writers; mu guards consistency between the rules
	// checked and the store written.
	wmu sync.Mutex
	mu  sync.RWMutex

	pubMu  sync.RWMutex
	public string

	changes chan Change
	done    chan struct{}
	closeMu sync.Once
}

// New makes a VTN. It does not listen: serve it with net/http (it is an
// http.Handler) or use ListenAndServe.
func New(cfg Config) (*VTN, error) {
	v := &VTN{cfg: cfg, clients: map[string]*Client{}, done: make(chan struct{})}
	c := &v.cfg
	c.BasePath = strings.TrimRight(c.BasePath, "/")
	if c.BasePath != "" && !strings.HasPrefix(c.BasePath, "/") {
		return nil, fmt.Errorf("vtn: BasePath %q must start with /", c.BasePath)
	}
	switch c.Version {
	case "":
		c.Version = Version31
	case Version31, Version30:
	default:
		return nil, fmt.Errorf("vtn: Version %q is not %s or %s", c.Version, Version31, Version30)
	}
	switch c.EventOrder {
	case "", EventsOldestFirst, EventsByPriority:
	default:
		return nil, fmt.Errorf("vtn: EventOrder %q is not %s or %s", c.EventOrder, EventsOldestFirst, EventsByPriority)
	}
	if c.TokenLifetime <= 0 {
		c.TokenLifetime = time.Hour
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	v.log = c.Logger
	if v.log == nil {
		v.log = slog.New(slog.DiscardHandler)
	}
	if len(c.Clients) == 0 && c.Authenticator == nil && !c.AnonymousRead {
		return nil, errors.New("vtn: give Clients, an Authenticator or AnonymousRead")
	}
	for i := range c.Clients {
		cl := &c.Clients[i]
		switch {
		case cl.ClientID == "" || cl.Secret == "":
			return nil, fmt.Errorf("vtn: client %d needs ClientID and Secret", i+1)
		case len(cl.ClientID) > 128:
			return nil, fmt.Errorf("vtn: client ID %q is longer than 128 characters", cl.ClientID)
		case cl.Role != RoleBL && cl.Role != RoleVEN:
			return nil, fmt.Errorf("vtn: client %s: role %q is not BL or VEN", cl.ClientID, cl.Role)
		case cl.ClientID == InternalClientID:
			return nil, fmt.Errorf("vtn: client ID %s is reserved", cl.ClientID)
		case v.clients[cl.ClientID] != nil:
			return nil, fmt.Errorf("vtn: client ID %s is listed twice", cl.ClientID)
		}
		for _, s := range cl.Scopes {
			if !contains(v.roleScopes(cl.Role), s) {
				return nil, fmt.Errorf("vtn: client %s: scope %s is not one of role %s's", cl.ClientID, s, cl.Role)
			}
		}
		v.clients[cl.ClientID] = cl
	}
	if c.TokenKey != nil {
		if len(c.TokenKey) < 32 {
			return nil, errors.New("vtn: TokenKey must be at least 32 bytes")
		}
		v.key = append([]byte(nil), c.TokenKey...)
	} else {
		v.key = make([]byte, 32)
		_, _ = rand.Read(v.key)
	}
	v.store = c.Store
	if v.store == nil {
		v.store = NewMemoryStore()
	}
	v.public = strings.TrimRight(c.PublicURL, "/")
	hooks, err := newDeliverer(v, c.Webhooks)
	if err != nil {
		return nil, err
	}
	v.hooks = hooks
	v.changes = make(chan Change, 1024)
	go v.changeLoop()
	v.mux = v.routes()
	return v, nil
}

// Close stops notification delivery. Requests still being served may
// finish; new changes are not notified.
func (v *VTN) Close() error {
	v.closeMu.Do(func() {
		close(v.done)
		v.hooks.close()
	})
	return nil
}

// SetPublicURL sets how clients reach the VTN, up to BasePath (see
// Config.PublicURL); useful when the address is known only once
// listening.
func (v *VTN) SetPublicURL(u string) {
	v.pubMu.Lock()
	v.public = strings.TrimRight(u, "/")
	v.pubMu.Unlock()
}

// ServeHTTP answers the OpenADR 3 API.
func (v *VTN) ServeHTTP(w http.ResponseWriter, r *http.Request) { v.mux.ServeHTTP(w, r) }

// ListenAndServe serves the VTN on addr until ctx ends (TLS when
// certFile and keyFile are given).
func (v *VTN) ListenAndServe(ctx context.Context, addr, certFile, keyFile string) error {
	srv := &http.Server{Addr: addr, Handler: v, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
	errc := make(chan error, 1)
	go func() {
		if certFile != "" {
			errc <- srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func (v *VTN) now() time.Time { return v.cfg.Now() }

func (v *VTN) stamp() string { return v.now().UTC().Format("2006-01-02T15:04:05.000Z") }

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// baseURL is how the client of r reaches the VTN.
func (v *VTN) baseURL(r *http.Request) string {
	v.pubMu.RLock()
	p := v.public
	v.pubMu.RUnlock()
	if p != "" {
		return p
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + v.cfg.BasePath
}

func (v *VTN) rel(r *http.Request) string { return strings.TrimPrefix(r.URL.Path, v.cfg.BasePath) }

func (v *VTN) changeLoop() {
	for {
		select {
		case <-v.done:
			return
		case c := <-v.changes:
			if v.cfg.OnChange != nil {
				v.cfg.OnChange(c)
			}
		}
	}
}

// ---- answers ----------------------------------------------------------------

// reply writes a JSON answer, gzip-compressed when the client accepts it,
// after the validator's check.
func (v *VTN) reply(w http.ResponseWriter, r *http.Request, status int, val any) {
	body, err := json.Marshal(val)
	if err != nil {
		status, body = 500, []byte(`{"title":"Internal Server Error","status":500}`)
	}
	if v.cfg.Validator != nil && status < 300 {
		if verr := v.cfg.Validator.Response(r.Method, v.rel(r), status, "application/json", body); verr != nil {
			v.log.Error("OpenADR 3 VTN answer fails the OpenAPI definition", "path", r.URL.Path, "error", verr)
			status = 500
			body, _ = json.Marshal(map[string]any{"title": "Internal Server Error", "status": 500,
				"detail": "the answer does not match the OpenAPI definition"})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") && len(body) > 512 {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(body)
		_ = zw.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		body = buf.Bytes()
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// problem answers an error as a problem object.
func (v *VTN) problem(w http.ResponseWriter, r *http.Request, err error) {
	var p *oadr3.Problem
	if !errors.As(err, &p) {
		v.log.Error("OpenADR 3 VTN request failed", "path", r.URL.Path, "error", err)
		p = &oadr3.Problem{Status: 500, Title: "Internal Server Error", Detail: "the request could not be carried out"}
	}
	if p.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="openadr3"`)
	}
	o := map[string]any{"type": "about:blank", "title": p.Title, "status": p.Status, "instance": r.URL.Path}
	if p.Detail != "" {
		o["detail"] = p.Detail
	}
	v.reply(w, r, p.Status, o)
}

// IsStatus says whether err is a problem with the given HTTP status (what
// the VTN's methods return for refused changes).
func IsStatus(err error, status int) bool {
	var p *oadr3.Problem
	return errors.As(err, &p) && p.Status == status
}

func unauthorized(detail string) error {
	return &oadr3.Problem{Status: 401, Title: "Unauthorized", Detail: detail}
}

// body reads a JSON request body.
func (v *VTN) body(w http.ResponseWriter, r *http.Request) (Object, error) {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		return nil, oadr3.BadRequest("the body must be application/json")
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20))
	if err != nil {
		return nil, oadr3.BadRequest("the body cannot be read: %v", err)
	}
	if v.cfg.Validator != nil {
		if err := v.cfg.Validator.Request(r.Method, v.rel(r), r.URL.Query(), "application/json", b); err != nil {
			return nil, oadr3.BadRequest("the body does not match the OpenAPI definition: %v", err)
		}
	}
	var o Object
	if err := json.Unmarshal(b, &o); err != nil || o == nil {
		return nil, oadr3.BadRequest("the body is not a JSON object")
	}
	return o, nil
}

// ---- routes -------------------------------------------------------------------

// collection describes one object collection's endpoints.
type collection struct {
	path  string
	typ   string
	read  string
	write string
}

var collections = []collection{
	{"/programs", oadr3.TypeProgram, ScopeReadTargets, ScopeWritePrograms},
	{"/events", oadr3.TypeEvent, ScopeReadTargets, ScopeWriteEvents},
	{"/reports", oadr3.TypeReport, ScopeReadVenObjects, ScopeWriteReports},
	{"/subscriptions", oadr3.TypeSubscription, ScopeReadVenObjects, ScopeWriteSubscriptions},
	{"/vens", oadr3.TypeVEN, ScopeReadVenObjects, ScopeWriteVens},
	{"/resources", oadr3.TypeResource, ScopeReadVenObjects, ScopeWriteVens},
}

func (v *VTN) routes() *http.ServeMux {
	mux := http.NewServeMux()
	b := v.cfg.BasePath
	for _, c := range collections {
		mux.HandleFunc("GET "+b+c.path, func(w http.ResponseWriter, r *http.Request) { v.search(w, r, c) })
		mux.HandleFunc("POST "+b+c.path, func(w http.ResponseWriter, r *http.Request) { v.create(w, r, c) })
		mux.HandleFunc("GET "+b+c.path+"/{id}", func(w http.ResponseWriter, r *http.Request) { v.readOne(w, r, c) })
		mux.HandleFunc("PUT "+b+c.path+"/{id}", func(w http.ResponseWriter, r *http.Request) { v.update(w, r, c) })
		mux.HandleFunc("DELETE "+b+c.path+"/{id}", func(w http.ResponseWriter, r *http.Request) { v.remove(w, r, c) })
	}
	mux.HandleFunc("GET "+b+"/auth/server", v.authServer)
	mux.HandleFunc("POST "+b+"/auth/token", v.authToken)
	if v.cfg.Version == Version31 {
		mux.HandleFunc("GET "+b+"/notifiers", v.notifiers)
		mux.HandleFunc("GET "+b+"/notifiers/mqtt/topics/{rest...}", v.mqttTopics)
	}
	mux.HandleFunc(b+"/", func(w http.ResponseWriter, r *http.Request) {
		v.problem(w, r, oadr3.NotFound("unrecognised URL %s %s", r.Method, r.URL.Path))
	})
	return mux
}

func (v *VTN) search(w http.ResponseWriter, r *http.Request, c collection) {
	who, err := v.access(r, c.read, c.typ == oadr3.TypeProgram || c.typ == oadr3.TypeEvent)
	if err != nil {
		v.problem(w, r, err)
		return
	}
	if v.cfg.Validator != nil {
		if err := v.cfg.Validator.Request(r.Method, v.rel(r), r.URL.Query(), "", nil); err != nil {
			v.problem(w, r, oadr3.BadRequest("%v", err))
			return
		}
	}
	q, err := v.parseQuery(c.typ, r.URL.Query())
	if err != nil {
		v.problem(w, r, err)
		return
	}
	out, err := v.find(r.Context(), who, c.typ, q)
	if err != nil {
		v.problem(w, r, err)
		return
	}
	v.reply(w, r, http.StatusOK, v.outList(c.typ, out))
}

func (v *VTN) readOne(w http.ResponseWriter, r *http.Request, c collection) {
	who, err := v.access(r, c.read, c.typ == oadr3.TypeProgram || c.typ == oadr3.TypeEvent)
	if err != nil {
		v.problem(w, r, err)
		return
	}
	id := r.PathValue("id")
	var targets []string
	if c.typ == oadr3.TypeProgram || c.typ == oadr3.TypeEvent {
		qv := url.Values{}
		for _, k := range []string{"targets", "targetType", "targetValues"} {
			if x, ok := r.URL.Query()[k]; ok {
				qv[k] = x
			}
		}
		q, err := v.parseQuery(c.typ, qv)
		if err != nil {
			v.problem(w, r, err)
			return
		}
		targets = q.targets
	}
	o, err := v.readVisible(r.Context(), who, c.typ, id, targets)
	if err != nil {
		v.problem(w, r, err)
		return
	}
	v.reply(w, r, http.StatusOK, v.out(c.typ, o))
}

func (v *VTN) create(w http.ResponseWriter, r *http.Request, c collection) {
	v.write(w, r, c, "", http.StatusCreated)
}

func (v *VTN) update(w http.ResponseWriter, r *http.Request, c collection) {
	v.write(w, r, c, r.PathValue("id"), http.StatusOK)
}

func (v *VTN) write(w http.ResponseWriter, r *http.Request, c collection, id string, status int) {
	who, err := v.access(r, c.write, false)
	if err != nil {
		v.problem(w, r, err)
		return
	}
	body, err := v.body(w, r)
	if err != nil {
		v.problem(w, r, err)
		return
	}
	o, err := v.apply(r.Context(), who, c.typ, id, body)
	if err != nil {
		v.problem(w, r, err)
		return
	}
	v.reply(w, r, status, v.out(c.typ, o))
}

func (v *VTN) remove(w http.ResponseWriter, r *http.Request, c collection) {
	who, err := v.access(r, c.write, false)
	if err != nil {
		v.problem(w, r, err)
		return
	}
	o, err := v.delete(r.Context(), who, c.typ, r.PathValue("id"))
	if err != nil {
		v.problem(w, r, err)
		return
	}
	v.reply(w, r, http.StatusOK, v.out(c.typ, o))
}

// ---- business logic in the same process ----------------------------------------

var internalBL = &Principal{ClientID: InternalClientID, Role: RoleBL}

// Create creates an object as business logic and gives it as stored.
func (v *VTN) Create(ctx context.Context, typ string, o Object) (Object, error) {
	return v.apply(ctx, v.internal(), typ, "", v.blForm(typ, o))
}

// Update replaces the object typ/id as business logic.
func (v *VTN) Update(ctx context.Context, typ, id string, o Object) (Object, error) {
	return v.apply(ctx, v.internal(), typ, id, v.blForm(typ, o))
}

// Delete deletes the object typ/id (a ven with its resources).
func (v *VTN) Delete(ctx context.Context, typ, id string) (Object, error) {
	return v.delete(ctx, v.internal(), typ, id)
}

// Get gives one object as stored (with every target).
func (v *VTN) Get(ctx context.Context, typ, id string) (Object, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	o, err := v.store.Get(ctx, typ, id)
	if errors.Is(err, ErrNotFound) {
		return nil, oadr3.NotFound("%s %s not found", strings.ToLower(typ), id)
	}
	return o, err
}

// List gives every object of a type, oldest first.
func (v *VTN) List(ctx context.Context, typ string) ([]Object, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.store.List(ctx, typ)
}

func (v *VTN) internal() *Principal {
	p := *internalBL
	p.Scopes = v.roleScopes(RoleBL)
	return &p
}

// blForm adds the business-logic request form to ven and resource
// objects written through the VTN's methods, when missing.
// The object is also put in its JSON form (numbers as float64, lists as
// []any), as a request body would be.
func (v *VTN) blForm(typ string, o Object) Object {
	o = oadr3.Clone(o)
	if o == nil {
		o = Object{}
	}
	if v.cfg.Version != Version31 || o["objectType"] != nil {
		return o
	}
	switch typ {
	case oadr3.TypeVEN:
		o["objectType"] = "BL_VEN_REQUEST"
	case oadr3.TypeResource:
		o["objectType"] = "BL_RESOURCE_REQUEST"
	}
	return o
}

// Status reports the VTN's state.
type Status struct {
	// Objects counts the objects per type.
	Objects map[string]int
	// BrokenCallbacks are callbacks skipped after repeated failures, until
	// their subscription is written again.
	BrokenCallbacks []BrokenCallback
	// Queued is the number of notifications waiting for delivery.
	Queued int
}

// BrokenCallback is a callback marked broken.
type BrokenCallback struct {
	SubscriptionID, URL string
	Since               time.Time
}

// Status gives the VTN's state.
func (v *VTN) Status() Status {
	st := Status{Objects: map[string]int{}}
	v.mu.RLock()
	for _, t := range oadr3.ObjectTypes {
		l, _ := v.store.List(context.Background(), t)
		st.Objects[t] = len(l)
	}
	v.mu.RUnlock()
	st.BrokenCallbacks, st.Queued = v.hooks.status()
	return st
}
