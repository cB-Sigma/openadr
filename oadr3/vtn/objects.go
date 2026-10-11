// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

// Reading and writing objects: queries and filters, object privacy, the
// rules applied to a client's representation, and the notifications a
// change causes.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cB-Sigma/openadr/oadr3"
)

var str, strs = oadr3.Str, oadr3.Strs

// ---- queries -------------------------------------------------------------------

type query struct {
	skip, limit int
	targets     []string
	filters     map[string]string
	active      *bool
}

// queryParams are the filters each collection accepts besides skip and
// limit (and targets, or targetType and targetValues in 3.0).
var queryParams = map[string][]string{
	oadr3.TypeProgram:      {"targets"},
	oadr3.TypeEvent:        {"programID", "targets", "active"},
	oadr3.TypeReport:       {"programID", "eventID", "clientName"},
	oadr3.TypeSubscription: {"programID", "clientName", "objects"},
	oadr3.TypeVEN:          {"venName", "targets"},
	oadr3.TypeResource:     {"resourceName", "venID", "targets"},
}

func (v *VTN) parseQuery(typ string, q url.Values) (query, error) {
	out := query{limit: oadr3.MaxLimit, filters: map[string]string{}}
	allowed := queryParams[typ]
	targetsOK := contains(allowed, "targets") || (v.cfg.Version == Version30 && typ != oadr3.TypeReport)
	var tType string
	var tValues []string
	for k, x := range q {
		switch k {
		case "skip", "limit":
			n, err := strconv.Atoi(x[0])
			if err != nil || n < 0 || n > 1<<31-1 {
				return out, oadr3.BadRequest("%s must be a non-negative integer", k)
			}
			if k == "skip" {
				out.skip = n
			} else {
				if n > oadr3.MaxLimit {
					return out, oadr3.BadRequest("limit may be at most %d", oadr3.MaxLimit)
				}
				out.limit = n
			}
		case "targets":
			if !targetsOK || v.cfg.Version == Version30 {
				return out, oadr3.BadRequest("query parameter %s is not defined here", k)
			}
			for _, s := range x {
				for _, t := range strings.Split(s, ",") {
					if t = strings.TrimSpace(t); t != "" {
						out.targets = append(out.targets, t)
					}
				}
			}
		case "targetType", "targetValues":
			if !targetsOK || v.cfg.Version != Version30 {
				return out, oadr3.BadRequest("query parameter %s is not defined here", k)
			}
			if k == "targetType" {
				tType = x[0]
			} else {
				for _, s := range x {
					for _, t := range strings.Split(s, ",") {
						if t = strings.TrimSpace(t); t != "" {
							tValues = append(tValues, t)
						}
					}
				}
			}
		case "active":
			if !contains(allowed, k) {
				return out, oadr3.BadRequest("query parameter %s is not defined here", k)
			}
			b, err := strconv.ParseBool(x[0])
			if err != nil {
				return out, oadr3.BadRequest("active must be true or false")
			}
			out.active = &b
		default:
			if !contains(allowed, k) {
				return out, oadr3.BadRequest("query parameter %s is not defined here", k)
			}
			out.filters[k] = x[0]
		}
	}
	if tType != "" || len(tValues) > 0 {
		if tType == "" || len(tValues) == 0 {
			return out, oadr3.BadRequest("targetType and targetValues go together")
		}
		for _, x := range tValues {
			out.targets = append(out.targets, target30(tType, x))
		}
	}
	return out, nil
}

// matches applies the filters (all must hold). Called with v.mu held.
func (v *VTN) matches(ctx context.Context, typ string, o Object, q query, now time.Time) (bool, error) {
	for k, x := range q.filters {
		switch k {
		case "programID":
			if typ == oadr3.TypeReport {
				if pid := str(o, "programID"); pid != "" {
					if pid != x {
						return false, nil
					}
					continue
				}
				ev, err := v.store.Get(ctx, oadr3.TypeEvent, str(o, "eventID"))
				if errors.Is(err, ErrNotFound) {
					return false, nil
				} else if err != nil {
					return false, err
				}
				if str(ev, "programID") != x {
					return false, nil
				}
				continue
			}
			if str(o, "programID") != x {
				return false, nil
			}
		case "objects":
			found := false
			for _, op := range listOf(o["objectOperations"]) {
				if contains(strs(op["objects"]), x) {
					found = true
				}
			}
			if !found {
				return false, nil
			}
		default:
			if str(o, k) != x {
				return false, nil
			}
		}
	}
	if q.active != nil && *q.active && typ == oadr3.TypeEvent && oadr3.Transpired(o, now) {
		return false, nil
	}
	return true, nil
}

func listOf(x any) []map[string]any {
	l, _ := x.([]any)
	out := make([]map[string]any, 0, len(l))
	for _, e := range l {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// ---- privacy -------------------------------------------------------------------

// grants is what business logic granted VEN clients: the targets of their
// vens and of those vens' resources.
type grants struct {
	targets map[string][]string
	hasVen  map[string]bool
}

// loadGrants reads every ven and resource. Called with v.mu held.
func (v *VTN) loadGrants(ctx context.Context) (*grants, error) {
	g := &grants{targets: map[string][]string{}, hasVen: map[string]bool{}}
	vens, err := v.store.List(ctx, oadr3.TypeVEN)
	if err != nil {
		return nil, err
	}
	res, err := v.store.List(ctx, oadr3.TypeResource)
	if err != nil {
		return nil, err
	}
	owner := map[string]string{}
	for _, x := range vens {
		c := str(x, "clientID")
		if c == "" {
			continue
		}
		owner[str(x, "id")] = c
		g.hasVen[c] = true
		g.targets[c] = append(g.targets[c], strs(x["targets"])...)
	}
	for _, r := range res {
		if c := owner[str(r, "venID")]; c != "" {
			g.targets[c] = append(g.targets[c], strs(r["targets"])...)
		}
	}
	return g, nil
}

// view gives what p may see of o (programs and events read by a VEN show
// only the targets it matched), or false. reqTargets are the targets the
// reader named (in its query, or its subscription's targets).
func view(p *Principal, g *grants, typ string, o Object, reqTargets []string) (Object, bool) {
	objTargets := strs(o["targets"])
	switch typ {
	case oadr3.TypeProgram, oadr3.TypeEvent:
		if p.BL() {
			if len(reqTargets) > 0 && !intersects(objTargets, reqTargets) {
				return nil, false
			}
			return o, true
		}
		if len(objTargets) == 0 {
			return o, true
		}
		if p == nil || g == nil || !g.hasVen[p.ClientID] {
			return nil, false
		}
		granted := g.targets[p.ClientID]
		var matched []string
		for _, t := range reqTargets {
			if contains(granted, t) && contains(objTargets, t) && !contains(matched, t) {
				matched = append(matched, t)
			}
		}
		if len(matched) == 0 {
			return nil, false
		}
		c := oadr3.Clone(o)
		c["targets"] = matched
		return c, true
	default:
		if p == nil {
			return nil, false
		}
		if !p.BL() && str(o, "clientID") != p.ClientID {
			return nil, false
		}
		if len(reqTargets) > 0 && typ != oadr3.TypeReport && !intersects(objTargets, reqTargets) {
			return nil, false
		}
		return o, true
	}
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}

// find answers a search.
func (v *VTN) find(ctx context.Context, p *Principal, typ string, q query) ([]Object, error) {
	now := v.now()
	v.mu.RLock()
	defer v.mu.RUnlock()
	all, err := v.store.List(ctx, typ)
	if err != nil {
		return nil, err
	}
	if typ == oadr3.TypeEvent && v.cfg.EventOrder == EventsByPriority {
		sortByPriority(all)
	}
	var g *grants
	if !p.BL() && (typ == oadr3.TypeProgram || typ == oadr3.TypeEvent) {
		if g, err = v.loadGrants(ctx); err != nil {
			return nil, err
		}
	}
	out := []Object{}
	skipped := 0
	for _, o := range all {
		if len(out) >= q.limit {
			break
		}
		ok, err := v.matches(ctx, typ, o, q, now)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		x, ok := view(p, g, typ, o, q.targets)
		if !ok {
			continue
		}
		if skipped < q.skip {
			skipped++
			continue
		}
		out = append(out, x)
	}
	return out, nil
}

// sortByPriority orders events most urgent first: by priority (a lower
// number first, no priority last), then newest first.
func sortByPriority(l []Object) {
	prio := func(o Object) float64 {
		if f, ok := o["priority"].(float64); ok {
			return f
		}
		return math.Inf(1)
	}
	sort.SliceStable(l, func(i, j int) bool {
		a, b := prio(l[i]), prio(l[j])
		if a != b {
			return a < b
		}
		ca, cb := str(l[i], "createdDateTime"), str(l[j], "createdDateTime")
		if ca != cb {
			return ca > cb
		}
		return str(l[i], "id") > str(l[j], "id")
	})
}

// readVisible gives one object p may see; an object it may not see is not
// found.
func (v *VTN) readVisible(ctx context.Context, p *Principal, typ, id string, targets []string) (Object, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	o, err := v.store.Get(ctx, typ, id)
	if errors.Is(err, ErrNotFound) {
		return nil, oadr3.NotFound("%s %s not found", strings.ToLower(typ), id)
	} else if err != nil {
		return nil, err
	}
	g, err := v.loadGrants(ctx)
	if err != nil {
		return nil, err
	}
	x, ok := view(p, g, typ, o, targets)
	if !ok {
		return nil, oadr3.NotFound("%s %s not found", strings.ToLower(typ), id)
	}
	return x, nil
}

// ---- writes --------------------------------------------------------------------

var lastID atomic.Int64

// nextID gives an object ID that sorts after every earlier one: the time
// in nanoseconds (kept strictly increasing) and random digits.
func nextID() string {
	n := time.Now().UnixNano()
	for {
		last := lastID.Load()
		if n <= last {
			n = last + 1
		}
		if lastID.CompareAndSwap(last, n) {
			break
		}
	}
	return fmt.Sprintf("%016x", n) + newID()[:8]
}

// apply creates (id "") or replaces the object typ/id from a client's
// representation, as p.
func (v *VTN) apply(ctx context.Context, p *Principal, typ, id string, body Object) (Object, error) {
	body = v.in(typ, p, body)
	// Business logic writing a resource without its clientID (which the
	// 3.1.0 definition requires; openleadr-rs's client leaves it out)
	// gets the clientID of the resource's ven.
	if typ == oadr3.TypeResource && p.BL() && body["objectType"] == "BL_RESOURCE_REQUEST" && body["clientID"] == nil {
		v.mu.RLock()
		ven, err := v.store.Get(ctx, oadr3.TypeVEN, str(body, "venID"))
		v.mu.RUnlock()
		if err == nil && str(ven, "clientID") != "" {
			body = oadr3.Clone(body)
			body["clientID"] = ven["clientID"]
		}
	}
	o, err := oadr3.CheckRequest(typ, body)
	if err != nil {
		return nil, err
	}
	// Webhook callbacks are checked before anything is locked (the check
	// is a network round trip).
	if typ == oadr3.TypeSubscription {
		if err := v.hooks.checkCallbacks(ctx, o); err != nil {
			return nil, err
		}
	}
	v.wmu.Lock()
	defer v.wmu.Unlock()
	v.mu.Lock()
	var old Object
	if id != "" {
		old, err = v.store.Get(ctx, typ, id)
		if errors.Is(err, ErrNotFound) {
			v.mu.Unlock()
			return nil, oadr3.NotFound("%s %s not found", strings.ToLower(typ), id)
		} else if err != nil {
			v.mu.Unlock()
			return nil, err
		}
		if _, visible := view(p, nil, typ, old, strs(old["targets"])); !visible && !p.BL() {
			v.mu.Unlock()
			return nil, oadr3.NotFound("%s %s not found", strings.ToLower(typ), id)
		}
		if (typ == oadr3.TypeProgram || typ == oadr3.TypeEvent) && !p.BL() {
			v.mu.Unlock()
			return nil, oadr3.Forbidden("only business logic writes %ss", strings.ToLower(typ))
		}
	}
	if err := v.rules(ctx, p, typ, id, o, old); err != nil {
		v.mu.Unlock()
		return nil, err
	}
	op := "UPDATE"
	stamp := v.stamp()
	if old == nil {
		op = "CREATE"
		id = nextID()
		o["createdDateTime"] = stamp
	} else {
		o["createdDateTime"] = old["createdDateTime"]
		if prev := str(old, "modificationDateTime"); stamp <= prev {
			if t, err := time.Parse(time.RFC3339Nano, prev); err == nil {
				stamp = t.Add(time.Millisecond).UTC().Format("2006-01-02T15:04:05.000Z")
			}
		}
	}
	o["id"] = id
	o["modificationDateTime"] = stamp
	o["objectType"] = typ
	if err := v.store.Put(ctx, typ, o); err != nil {
		v.mu.Unlock()
		return nil, err
	}
	notes, err := v.fanOut(ctx, op, typ, o)
	v.mu.Unlock()
	if err != nil {
		v.log.Error("OpenADR 3 VTN cannot work out the notifications of a change", "error", err)
	}
	v.hooks.enqueue(notes)
	if typ == oadr3.TypeSubscription {
		v.hooks.rewritten(id)
	}
	v.changed(Change{Operation: op, ObjectType: typ, Object: oadr3.Clone(o), ClientID: p.ClientID})
	return o, nil
}

func (v *VTN) changed(c Change) {
	if v.cfg.OnChange == nil {
		return
	}
	select {
	case v.changes <- c:
	case <-v.done:
	}
}

// rules applies the type-specific rules to a checked representation o
// (with old the object it replaces, or nil). Called with v.mu held.
func (v *VTN) rules(ctx context.Context, p *Principal, typ, id string, o, old Object) error {
	exists := func(t, oid string) (bool, error) {
		_, err := v.store.Get(ctx, t, oid)
		if errors.Is(err, ErrNotFound) {
			return false, nil
		}
		return err == nil, err
	}
	switch typ {
	case oadr3.TypeProgram:
		all, err := v.store.List(ctx, oadr3.TypeProgram)
		if err != nil {
			return err
		}
		for _, x := range all {
			if str(x, "id") != id && str(x, "programName") == str(o, "programName") {
				return oadr3.Conflict("a program named %s exists", str(o, "programName"))
			}
		}
	case oadr3.TypeEvent:
		if ok, err := exists(oadr3.TypeProgram, str(o, "programID")); err != nil {
			return err
		} else if !ok {
			return oadr3.BadRequest("programID %s does not name a program", str(o, "programID"))
		}
	case oadr3.TypeReport:
		if ok, err := exists(oadr3.TypeEvent, str(o, "eventID")); err != nil {
			return err
		} else if !ok {
			return oadr3.BadRequest("eventID %s does not name an event", str(o, "eventID"))
		}
		o["clientID"] = p.ClientID
		if old != nil {
			o["clientID"] = old["clientID"]
		}
	case oadr3.TypeSubscription:
		if pid := str(o, "programID"); pid != "" {
			if ok, err := exists(oadr3.TypeProgram, pid); err != nil {
				return err
			} else if !ok {
				return oadr3.BadRequest("programID %s does not name a program", pid)
			}
		}
		o["clientID"] = p.ClientID
		if old != nil {
			o["clientID"] = old["clientID"]
		}
	case oadr3.TypeVEN:
		form := o["objectType"]
		delete(o, "objectType")
		if p.BL() {
			if v.cfg.Version == Version31 && form != "BL_VEN_REQUEST" {
				return oadr3.BadRequest("business logic writes vens with objectType BL_VEN_REQUEST and a clientID")
			}
			if str(o, "clientID") == "" && old != nil {
				o["clientID"] = old["clientID"]
			}
		} else {
			if v.cfg.Version == Version31 && form != "VEN_VEN_REQUEST" {
				return oadr3.Forbidden("a VEN writes its ven with objectType VEN_VEN_REQUEST")
			}
			// Only business logic grants targets.
			delete(o, "targets")
			if old != nil && old["targets"] != nil {
				o["targets"] = old["targets"]
			}
			o["clientID"] = p.ClientID
		}
		all, err := v.store.List(ctx, oadr3.TypeVEN)
		if err != nil {
			return err
		}
		for _, x := range all {
			if str(x, "id") != id && str(x, "venName") == str(o, "venName") {
				return oadr3.Conflict("a ven named %s exists", str(o, "venName"))
			}
		}
	case oadr3.TypeResource:
		form := o["objectType"]
		delete(o, "objectType")
		ven, err := v.store.Get(ctx, oadr3.TypeVEN, str(o, "venID"))
		if errors.Is(err, ErrNotFound) {
			return oadr3.BadRequest("venID %s does not name a ven", str(o, "venID"))
		} else if err != nil {
			return err
		}
		if p.BL() {
			if v.cfg.Version == Version31 && form != "BL_RESOURCE_REQUEST" {
				return oadr3.BadRequest("business logic writes resources with objectType BL_RESOURCE_REQUEST and a clientID")
			}
			if str(o, "clientID") == "" {
				if old != nil && str(old, "clientID") != "" {
					o["clientID"] = old["clientID"]
				} else if c := str(ven, "clientID"); c != "" {
					o["clientID"] = c
				}
			}
		} else {
			if v.cfg.Version == Version31 && form != "VEN_RESOURCE_REQUEST" {
				return oadr3.Forbidden("a VEN writes resources with objectType VEN_RESOURCE_REQUEST")
			}
			if str(ven, "clientID") != p.ClientID {
				return oadr3.Forbidden("ven %s belongs to another client", str(o, "venID"))
			}
			delete(o, "targets")
			if old != nil && old["targets"] != nil {
				o["targets"] = old["targets"]
			}
			o["clientID"] = p.ClientID
		}
		all, err := v.store.List(ctx, oadr3.TypeResource)
		if err != nil {
			return err
		}
		for _, x := range all {
			if str(x, "id") != id && str(x, "venID") == str(o, "venID") && str(x, "resourceName") == str(o, "resourceName") {
				return oadr3.Conflict("ven %s already has a resource named %s", str(o, "venID"), str(o, "resourceName"))
			}
		}
	}
	return nil
}

// delete removes an object p can see; deleting a ven deletes its
// resources too.
func (v *VTN) delete(ctx context.Context, p *Principal, typ, id string) (Object, error) {
	v.wmu.Lock()
	defer v.wmu.Unlock()
	v.mu.Lock()
	o, err := v.store.Get(ctx, typ, id)
	if errors.Is(err, ErrNotFound) {
		v.mu.Unlock()
		return nil, oadr3.NotFound("%s %s not found", strings.ToLower(typ), id)
	} else if err != nil {
		v.mu.Unlock()
		return nil, err
	}
	if _, visible := view(p, nil, typ, o, strs(o["targets"])); !visible && !p.BL() {
		v.mu.Unlock()
		return nil, oadr3.NotFound("%s %s not found", strings.ToLower(typ), id)
	}
	if (typ == oadr3.TypeProgram || typ == oadr3.TypeEvent) && !p.BL() {
		v.mu.Unlock()
		return nil, oadr3.Forbidden("only business logic deletes %ss", strings.ToLower(typ))
	}
	gone := []Object{o}
	if typ == oadr3.TypeVEN {
		res, err := v.store.List(ctx, oadr3.TypeResource)
		if err != nil {
			v.mu.Unlock()
			return nil, err
		}
		for _, r := range res {
			if str(r, "venID") == id {
				gone = append(gone, r)
			}
		}
	}
	// Notifications are worked out while the objects still exist (a
	// VEN's view of a deleted object depends on its grants).
	var notes []Delivery
	for _, x := range gone {
		n, err := v.fanOut(ctx, "DELETE", str(x, "objectType"), x)
		if err != nil {
			v.log.Error("OpenADR 3 VTN cannot work out the notifications of a change", "error", err)
		}
		notes = append(notes, n...)
	}
	for i := len(gone) - 1; i >= 0; i-- {
		x := gone[i]
		if err := v.store.Delete(ctx, str(x, "objectType"), str(x, "id")); err != nil {
			v.mu.Unlock()
			return nil, err
		}
	}
	v.mu.Unlock()
	v.hooks.enqueue(notes)
	for _, x := range gone {
		v.changed(Change{Operation: "DELETE", ObjectType: str(x, "objectType"), Object: x, ClientID: p.ClientID})
	}
	return o, nil
}

// ---- notifications ---------------------------------------------------------------

// subscriber is the principal a subscription acts for.
func (v *VTN) subscriber(sub Object) *Principal {
	id := str(sub, "clientID")
	if id == InternalClientID {
		return v.internal()
	}
	if c := v.clients[id]; c != nil {
		return &Principal{ClientID: c.ClientID, Role: c.Role, Scopes: v.clientScopes(c)}
	}
	// A client of an external authorisation server: its role is not
	// known here; it is treated as a VEN (it sees only what VENs see).
	return &Principal{ClientID: id, Role: RoleVEN, Scopes: v.roleScopes(RoleVEN)}
}

// inProgram says whether o belongs to program pid (objects with no
// program pass).
func (v *VTN) inProgram(ctx context.Context, typ string, o Object, pid string) bool {
	switch typ {
	case oadr3.TypeProgram:
		return str(o, "id") == pid
	case oadr3.TypeEvent, oadr3.TypeSubscription:
		return str(o, "programID") == pid
	case oadr3.TypeReport:
		if x := str(o, "programID"); x != "" {
			return x == pid
		}
		ev, err := v.store.Get(ctx, oadr3.TypeEvent, str(o, "eventID"))
		return err == nil && str(ev, "programID") == pid
	}
	return true
}

// fanOut lists the notifications a change causes. Called with v.mu held.
func (v *VTN) fanOut(ctx context.Context, op, typ string, o Object) ([]Delivery, error) {
	subs, err := v.store.List(ctx, oadr3.TypeSubscription)
	if err != nil {
		return nil, err
	}
	g, err := v.loadGrants(ctx)
	if err != nil {
		return nil, err
	}
	nid := newID() + newID()
	var out []Delivery
	for _, sub := range subs {
		who := v.subscriber(sub)
		if pid := str(sub, "programID"); pid != "" && !v.inProgram(ctx, typ, o, pid) {
			continue
		}
		x, ok := view(who, g, typ, o, strs(sub["targets"]))
		if !ok {
			continue
		}
		x = v.out(typ, x)
		for _, oo := range listOf(sub["objectOperations"]) {
			if !contains(strs(oo["objects"]), typ) || !contains(strs(oo["operations"]), op) {
				continue
			}
			n := map[string]any{"objectType": typ, "operation": op, "object": x}
			if t := x["targets"]; t != nil && v.cfg.Version == Version31 {
				if l := strs(t); len(l) > 0 {
					n["targets"] = l
				}
			}
			bearer, _ := oo["bearerToken"].(string)
			out = append(out, Delivery{ID: nid, SubscriptionID: str(sub, "id"), ClientID: who.ClientID,
				URL: str(oo, "callbackUrl"), Bearer: bearer, Notification: n})
		}
	}
	if v.cfg.MQTT != nil && v.cfg.MQTT.Publisher != nil {
		out = append(out, v.mqttNotes(op, typ, o, g, nid)...)
	}
	return out, nil
}
