// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

// The MQTT notifier of OpenADR 3.1. The VTN publishes each notification
// through a Publisher you supply (a client of your broker, or an embedded
// one) and announces the binding in GET /notifiers. Clients log in to the
// broker with the OAUTH2_BEARER_TOKEN method: user name their client ID
// (or MQTTConfig.Username), password a token from the VTN; MQTTLogin and
// MQTTAllowed give the broker's authentication and subscribe rules. Only
// the VTN publishes; business logic may read every topic, a VEN only the
// topics of its own vens (vens/{venID}/…), where the VTN publishes just
// what that VEN may read. The topic names are the VTN's choice, listed
// through /notifiers/mqtt/topics/…:
//
//	programs/{create,update,delete}          programs/{programID}/{update,delete}
//	events/{…}   programs/{programID}/events/{…}   reports/{…}   subscriptions/{…}
//	vens/{…}     vens/{venID}/{update,delete}      resources/{…}
//	vens/{venID}/events/{…}   vens/{venID}/programs/{…}   vens/{venID}/resources/{…}
//
// and "<prefix>/+" for every operation.

import (
	"context"
	"net/http"
	"strings"

	"github.com/cB-Sigma/openadr/oadr3"
)

// Publisher publishes an MQTT message (QoS 1, not retained, is what
// OpenADR 3 clients expect).
type Publisher interface {
	Publish(ctx context.Context, topic string, payload []byte) error
}

// MQTTConfig configures the MQTT notifier.
type MQTTConfig struct {
	Publisher Publisher
	// URIs are where clients connect, announced in GET /notifiers
	// (e.g. mqtts://vtn.example:8883).
	URIs []string
	// Username is announced for OAUTH2_BEARER_TOKEN logins (default
	// "{clientID}": each client's own ID).
	Username string
}

func (v *VTN) mqttUsername() string {
	if v.cfg.MQTT != nil && v.cfg.MQTT.Username != "" {
		return v.cfg.MQTT.Username
	}
	return "{clientID}"
}

// MQTTLogin checks a broker login as OAUTH2_BEARER_TOKEN describes: the
// password is a bearer token, the user name the client ID it was issued
// to (or the configured literal). It gives the client ID.
func (v *VTN) MQTTLogin(user, password string) (clientID string, ok bool) {
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	p, err := v.verify(req, password)
	if err != nil {
		return "", false
	}
	if want := v.mqttUsername(); want == "{clientID}" {
		if user != p.ClientID {
			return "", false
		}
	} else if user != want {
		return "", false
	}
	return p.ClientID, true
}

// MQTTAllowed is the broker's topic rule for a logged-in client: nobody
// but the VTN publishes; business logic reads every topic; a VEN reads
// only vens/{venID}/… of its own vens.
func (v *VTN) MQTTAllowed(clientID, topic string, write bool) bool {
	if write {
		return false
	}
	p := v.subscriber(Object{"clientID": clientID})
	if p.BL() {
		return true
	}
	parts := strings.Split(topic, "/")
	if len(parts) < 3 || parts[0] != "vens" || strings.ContainsAny(parts[1], "+#") {
		return false
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	ven, err := v.store.Get(context.Background(), oadr3.TypeVEN, parts[1])
	return err == nil && str(ven, "clientID") == clientID
}

var lowerOps = map[string]string{"CREATE": "create", "UPDATE": "update", "DELETE": "delete"}

// mqttNotes lists the MQTT publications a change causes. Called with v.mu
// held.
func (v *VTN) mqttNotes(op, typ string, o Object, g *grants, nid string) []Delivery {
	lop := lowerOps[op]
	if lop == "" {
		return nil
	}
	id := str(o, "id")
	var out []Delivery
	add := func(topic string, x Object) {
		out = append(out, Delivery{ID: nid, Topic: topic, Notification: map[string]any{"objectType": typ, "operation": op, "object": v.out(typ, x)}})
	}
	perVen := func(sub string) {
		vens, err := v.store.List(context.Background(), oadr3.TypeVEN)
		if err != nil {
			return
		}
		for _, ven := range vens {
			c := str(ven, "clientID")
			if c == "" {
				continue
			}
			who := v.subscriber(Object{"clientID": c})
			if who.BL() {
				continue
			}
			if x, ok := view(who, g, typ, o, g.targets[c]); ok {
				add("vens/"+str(ven, "id")+"/"+sub+"/"+lop, x)
			}
		}
	}
	switch typ {
	case oadr3.TypeProgram:
		add("programs/"+lop, o)
		if op != "CREATE" {
			add("programs/"+id+"/"+lop, o)
		}
		perVen("programs")
	case oadr3.TypeEvent:
		add("events/"+lop, o)
		add("programs/"+str(o, "programID")+"/events/"+lop, o)
		perVen("events")
	case oadr3.TypeReport:
		add("reports/"+lop, o)
	case oadr3.TypeSubscription:
		add("subscriptions/"+lop, o)
	case oadr3.TypeVEN:
		add("vens/"+lop, o)
		if op != "CREATE" {
			add("vens/"+id+"/"+lop, o)
		}
	case oadr3.TypeResource:
		add("resources/"+lop, o)
		add("vens/"+str(o, "venID")+"/resources/"+lop, o)
	}
	return out
}

// notifiers answers GET /notifiers. Any authenticated client may learn
// the bindings: VENs need them to use MQTT.
func (v *VTN) notifiers(w http.ResponseWriter, r *http.Request) {
	if _, err := v.access(r, ScopeReadAll, false); err != nil && !IsStatus(err, http.StatusForbidden) {
		v.problem(w, r, err)
		return
	}
	out := map[string]any{"WEBHOOK": true}
	if m := v.cfg.MQTT; m != nil && m.Publisher != nil {
		out["MQTT"] = map[string]any{"URIS": m.URIs, "serialization": "JSON",
			"authentication": map[string]any{"method": "OAUTH2_BEARER_TOKEN", "username": v.mqttUsername()}}
	}
	v.reply(w, r, http.StatusOK, out)
}

// mqttTopics answers GET /notifiers/mqtt/topics/….
func (v *VTN) mqttTopics(w http.ResponseWriter, r *http.Request) {
	rest := strings.Split(strings.Trim(r.PathValue("rest"), "/"), "/")
	scope := ScopeReadBL
	perObject := false
	var base string
	switch {
	case len(rest) == 1 && rest[0] == "programs":
		scope, base = ScopeReadTargets, "programs"
	case len(rest) == 2 && rest[0] == "programs":
		scope, base, perObject = ScopeReadTargets, "programs/"+rest[1], true
	case len(rest) == 3 && rest[0] == "programs" && rest[2] == "events":
		scope, base = ScopeReadTargets, "programs/"+rest[1]+"/events"
	case len(rest) == 1 && (rest[0] == "events" || rest[0] == "reports" || rest[0] == "subscriptions" || rest[0] == "vens" || rest[0] == "resources"):
		base = rest[0]
	case len(rest) == 2 && rest[0] == "vens":
		scope, base, perObject = ScopeReadVenObjects, "vens/"+rest[1], true
	case len(rest) == 3 && rest[0] == "vens" && (rest[2] == "events" || rest[2] == "programs" || rest[2] == "resources"):
		scope, base = ScopeReadVenObjects, "vens/"+rest[1]+"/"+rest[2]
	default:
		v.problem(w, r, oadr3.NotFound("no MQTT topics for %s", r.URL.Path))
		return
	}
	who, err := v.access(r, scope, false)
	if err != nil {
		v.problem(w, r, err)
		return
	}
	if v.cfg.MQTT == nil || v.cfg.MQTT.Publisher == nil {
		v.problem(w, r, oadr3.NotFound("this VTN has no MQTT notifier"))
		return
	}
	ctx := r.Context()
	v.mu.RLock()
	var missing error
	switch {
	case rest[0] == "programs" && len(rest) >= 2:
		if _, err := v.store.Get(ctx, oadr3.TypeProgram, rest[1]); err != nil {
			missing = oadr3.NotFound("program %s not found", rest[1])
		}
	case rest[0] == "vens" && len(rest) >= 2:
		ven, err := v.store.Get(ctx, oadr3.TypeVEN, rest[1])
		if err != nil || (!who.BL() && str(ven, "clientID") != who.ClientID) {
			missing = oadr3.NotFound("ven %s not found", rest[1])
		}
	}
	v.mu.RUnlock()
	if missing != nil {
		v.problem(w, r, missing)
		return
	}
	topics := map[string]any{"UPDATE": base + "/update", "DELETE": base + "/delete", "ALL": base + "/+"}
	if !perObject {
		topics["CREATE"] = base + "/create"
	}
	v.reply(w, r, http.StatusOK, map[string]any{"topics": topics})
}
