// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// evState is one event for one VEN.
type evState struct {
	ev     oadr2b.OadrEvent
	opt    string // optIn / optOut, "" before an answer
	locked bool   // the opt came from oadrCreateOpt (rule 206)
	acked  int64  // modification number last acknowledged, -1 none
}

// IntervalSpec is one interval of an event signal.
type IntervalSpec struct {
	Duration time.Duration
	Value    float64
}

// EventSpec describes an event with one signal; Build makes the
// oadrEvent. For anything else build an oadr2b.OadrEvent directly.
type EventSpec struct {
	ID            string
	MarketContext string
	// SignalName and SignalType default to SIMPLE and level.
	SignalName, SignalType string
	Start                  time.Time
	Intervals              []IntervalSpec
	// ResponseRequired is always (default) or never.
	ResponseRequired string
	Priority         *uint32
	Test             bool
	Comment          string
	// RampUp, Recovery, StartAfter (randomisation) and Notification are
	// the active period's optional durations.
	RampUp, Recovery, StartAfter, Notification time.Duration
	// Resources are the eiTarget's resourceIDs (the VTN adds the venID).
	Resources []string
}

// Build makes the event (modification number 0, status from now).
func (s EventSpec) Build() oadr2b.OadrEvent {
	name, typ := s.SignalName, s.SignalType
	if name == "" {
		name = "SIMPLE"
	}
	if typ == "" {
		typ = "level"
	}
	rr := s.ResponseRequired
	if rr == "" {
		rr = "always"
	}
	var total time.Duration
	ivs := make([]oadr2b.Interval, len(s.Intervals))
	for i, iv := range s.Intervals {
		// Rules 101-103: uid from 0, a duration each, no dtstart.
		ivs[i] = oadr2b.Interval{Duration: &oadr2b.DurationProp{Duration: oadr2b.FormatDuration(iv.Duration)},
			UID: &oadr2b.UID{Text: strconv.Itoa(i)}, SignalPayload: &oadr2b.SignalPayload{PayloadFloat: oadr2b.PayloadFloat{Value: iv.Value}}}
		total += iv.Duration
	}
	props := oadr2b.Properties{DtStart: oadr2b.DtStart{DateTime: oadr2b.FormatTime(s.Start)}, Duration: oadr2b.DurationProp{Duration: oadr2b.FormatDuration(total)},
		// Rule 105: x-eiNotification is always given.
		Notification: &oadr2b.DurationProp{Duration: oadr2b.FormatDuration(s.Notification)}}
	if s.StartAfter > 0 {
		props.Tolerance = &oadr2b.Tolerance{Tolerate: oadr2b.Tolerate{StartAfter: oadr2b.FormatDuration(s.StartAfter)}}
	}
	if s.RampUp > 0 {
		props.RampUp = &oadr2b.DurationProp{Duration: oadr2b.FormatDuration(s.RampUp)}
	}
	if s.Recovery > 0 {
		props.Recovery = &oadr2b.DurationProp{Duration: oadr2b.FormatDuration(s.Recovery)}
	}
	test := "false"
	if s.Test {
		test = "true"
	}
	now := time.Now()
	ev := oadr2b.OadrEvent{ResponseRequired: rr, EiEvent: oadr2b.EiEvent{
		Descriptor: oadr2b.EventDescriptor{EventID: s.ID, ModificationDateTime: oadr2b.FormatTime(now), Priority: s.Priority,
			MarketContext: oadr2b.MarketContext{MarketContext: s.MarketContext}, CreatedDateTime: oadr2b.FormatTime(now),
			TestEvent: test, VtnComment: s.Comment},
		ActivePeriod: oadr2b.ActivePeriod{Properties: props, Components: oadr2b.Components{Nil: "true"}},
		Signals: oadr2b.EventSignals{Signal: []oadr2b.EventSignal{{Intervals: oadr2b.Intervals{Interval: ivs}, SignalName: name,
			SignalType: typ, SignalID: s.ID + "-0", CurrentValue: &oadr2b.CurrentValue{}}}},
		Target: oadr2b.Target{ResourceID: slices.Clone(s.Resources)},
	}}
	ev.EiEvent.Descriptor.EventStatus = Status(ev.EiEvent, now)
	return ev
}

// window is an event's start, end (far future for an open-ended event)
// and randomisation window; ok is false when the times do not parse.
func window(e oadr2b.EiEvent) (start, end time.Time, startAfter time.Duration, ok bool) {
	p := e.ActivePeriod.Properties
	start, err := oadr2b.ParseTime(p.DtStart.DateTime)
	if err != nil {
		return start, end, 0, false
	}
	d, _ := oadr2b.ParseDuration(p.Duration.Duration)
	end = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	if d > 0 {
		end = start.Add(d) // rule 47: zero is an event without an end
	}
	if p.Tolerance != nil && p.Tolerance.Tolerate.StartAfter != "" {
		startAfter, _ = oadr2b.ParseDuration(p.Tolerance.Tolerate.StartAfter)
	}
	return start, end, startAfter, true
}

// Status is an event's eventStatus at now (rule 13): far, near from the
// start of the ramp-up period when one is given, active from dtstart,
// completed after the end; cancelled stays cancelled. An event whose
// times do not parse keeps its own status.
func Status(e oadr2b.EiEvent, now time.Time) string {
	if e.Descriptor.EventStatus == "cancelled" {
		return "cancelled"
	}
	start, end, _, ok := window(e)
	if !ok {
		return e.Descriptor.EventStatus
	}
	var ramp time.Duration
	if r := e.ActivePeriod.Properties.RampUp; r != nil {
		ramp, _ = oadr2b.ParseDuration(r.Duration)
	}
	switch {
	case !now.Before(end):
		return "completed"
	case !now.Before(start):
		return "active"
	case ramp > 0 && !now.Before(start.Add(-ramp)):
		return "near"
	}
	return "far"
}

// sendable is whether the event still goes to the VEN: pending and
// active events always; completed ones until the randomisation window
// has passed (rule 66); cancelled ones until the VEN acknowledged the
// cancellation, or, when no answer is asked for, until the end (rules 50
// and 52).
func (e *evState) sendable(now time.Time) bool {
	_, end, after, ok := window(e.ev.EiEvent)
	switch Status(e.ev.EiEvent, now) {
	case "completed":
		return ok && now.Before(end.Add(after))
	case "cancelled":
		if e.ev.ResponseRequired == "never" {
			return !ok || now.Before(end.Add(after))
		}
		return e.acked < int64(e.ev.EiEvent.Descriptor.ModificationNumber)
	}
	return true
}

// rank orders events for oadrDistributeEvent (rule 15): active events
// first, by priority (1 highest, none last), then by start; then the
// others by start.
func rank(a, b *evState, now time.Time) int {
	pa, pb := Status(a.ev.EiEvent, now) == "active", Status(b.ev.EiEvent, now) == "active"
	if pa != pb {
		if pa {
			return -1
		}
		return 1
	}
	if pa {
		prio := func(e *evState) uint64 {
			if p := e.ev.EiEvent.Descriptor.Priority; p != nil && *p != 0 {
				return uint64(*p)
			}
			return math.MaxUint64
		}
		if x, y := prio(a), prio(b); x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	sa, _, _, _ := window(a.ev.EiEvent)
	sb, _, _, _ := window(b.ev.EiEvent)
	return sa.Compare(sb)
}

// distributionLocked lists every event the VEN should see in rule 15's
// order and forgets events that are over; v.mu held.
func (v *VTN) distributionLocked(venID string, st *venState, requestID string, limit uint32, now time.Time) *oadr2b.DistributeEvent {
	de := &oadr2b.DistributeEvent{EiResponse: &oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, ResponseDescription: "OK", RequestID: requestID},
		RequestID: requestID, VtnID: v.cfg.VtnID}
	var list []*evState
	keep := st.order[:0]
	for _, id := range st.order {
		e := st.events[id]
		if !e.sendable(now) {
			delete(st.events, id)
			continue
		}
		keep = append(keep, id)
		list = append(list, e)
	}
	st.order = keep
	slices.SortStableFunc(list, func(a, b *evState) int { return rank(a, b, now) })
	for _, e := range list {
		ev := e.ev
		ev.EiEvent.Descriptor.EventStatus = Status(ev.EiEvent, now)
		if ev.EiEvent.Target.Empty() {
			// Rule 63: the target names the VEN.
			ev.EiEvent.Target.VenID = []string{venID}
		}
		de.Events = append(de.Events, ev)
		if limit > 0 && uint32(len(de.Events)) >= limit {
			break
		}
	}
	return de
}

func (v *VTN) hasEventsLocked(_ string, st *venState, now time.Time) bool {
	for _, e := range st.events {
		if e.sendable(now) {
			return true
		}
	}
	return false
}

// changedLocked marks the event list new for the VEN; v.mu held. It
// reports whether the VEN gets pushes.
func (st *venState) changedLocked() bool {
	st.eventsDirty = true
	st.eventsGen++
	return st.reg != nil && st.reg.Push
}

// AddEvent gives a new event to a registered VEN. The VEN gets it on its
// next poll, or pushed. Empty ResponseRequired is read as always and an
// empty createdDateTime is set to now; eventStatus is worked out from the
// active period each time the event is sent (Status).
func (v *VTN) AddEvent(venID string, ev oadr2b.OadrEvent) error {
	if _, err := v.registered(venID); err != nil {
		return err
	}
	id := ev.EiEvent.Descriptor.EventID
	if id == "" {
		return errors.New("the event has no eventID")
	}
	if ev.ResponseRequired == "" {
		ev.ResponseRequired = "always"
	}
	if ev.EiEvent.Descriptor.CreatedDateTime == "" {
		ev.EiEvent.Descriptor.CreatedDateTime = oadr2b.FormatTime(time.Now())
	}
	v.mu.Lock()
	st := v.stateLocked(venID)
	if _, dup := st.events[id]; dup {
		v.mu.Unlock()
		return fmt.Errorf("VEN %s already has event %s (use ModifyEvent)", venID, id)
	}
	st.events[id] = &evState{ev: ev, acked: -1}
	st.order = append(st.order, id)
	push := st.changedLocked()
	v.mu.Unlock()
	if push {
		v.kick(venID)
	}
	return nil
}

// ModifyEvent replaces an event the VEN has. Its modificationNumber
// becomes one more than the previous one unless ev's is higher (rule 20
// allows changes to pending and active events only; that is for the
// caller).
func (v *VTN) ModifyEvent(venID string, ev oadr2b.OadrEvent) error {
	id := ev.EiEvent.Descriptor.EventID
	return v.change(venID, id, func(old *evState) error {
		if old.ev.EiEvent.Descriptor.EventStatus == "cancelled" {
			return fmt.Errorf("event %s is cancelled", id)
		}
		if ev.ResponseRequired == "" {
			ev.ResponseRequired = old.ev.ResponseRequired
		}
		if ev.EiEvent.Descriptor.CreatedDateTime == "" {
			ev.EiEvent.Descriptor.CreatedDateTime = old.ev.EiEvent.Descriptor.CreatedDateTime
		}
		ev.EiEvent.Descriptor.ModificationNumber = max(ev.EiEvent.Descriptor.ModificationNumber, old.ev.EiEvent.Descriptor.ModificationNumber+1)
		ev.EiEvent.Descriptor.ModificationDateTime = oadr2b.FormatTime(time.Now())
		old.ev = ev
		return nil
	})
}

// CancelEvent cancels an event: its status becomes cancelled with the
// next modificationNumber. It is sent until the VEN acknowledges it.
func (v *VTN) CancelEvent(venID, eventID string) error {
	return v.change(venID, eventID, func(old *evState) error {
		d := &old.ev.EiEvent.Descriptor
		if d.EventStatus == "cancelled" {
			return nil
		}
		d.EventStatus = "cancelled"
		d.ModificationNumber++
		d.ModificationDateTime = oadr2b.FormatTime(time.Now())
		return nil
	})
}

func (v *VTN) change(venID, eventID string, f func(*evState) error) error {
	if _, err := v.registered(venID); err != nil {
		return err
	}
	v.mu.Lock()
	st := v.stateLocked(venID)
	e := st.events[eventID]
	if e == nil {
		v.mu.Unlock()
		return fmt.Errorf("VEN %s has no event %s", venID, eventID)
	}
	// A copy: distributions already made share the old one's slices.
	c := *e
	if err := f(&c); err != nil {
		v.mu.Unlock()
		return err
	}
	st.events[eventID] = &c
	push := st.changedLocked()
	v.mu.Unlock()
	if push {
		v.kick(venID)
	}
	return nil
}

// Events lists the events the VTN still sends to a VEN, in the order
// added: not those completed, nor cancelled ones the VEN acknowledged.
func (v *VTN) Events(venID string) []oadr2b.OadrEvent {
	v.mu.Lock()
	defer v.mu.Unlock()
	st := v.states[venID]
	if st == nil {
		return nil
	}
	now := time.Now()
	out := make([]oadr2b.OadrEvent, 0, len(st.order))
	for _, id := range st.order {
		if e := st.events[id]; e.sendable(now) {
			out = append(out, e.ev)
		}
	}
	return out
}

// OptState is the VEN's last answer to an event: optIn, optOut or "".
func (v *VTN) OptState(venID, eventID string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if st := v.states[venID]; st != nil {
		if e := st.events[eventID]; e != nil {
			return e.opt
		}
	}
	return ""
}

// createdEvent takes a VEN's answers to events and gives the code for
// the oadrResponse: 452 for an unknown eventID, 450 for a modification
// number other than the current one (rule 48).
func (v *VTN) createdEvent(ctx context.Context, venID string, ce *oadr2b.CreatedEvent) (string, string) {
	if c := ce.EiCreatedEvent.EiResponse.ResponseCode; c != "" && c != oadr2b.CodeOK {
		// Rule 25: a failed oadrCreatedEvent carries no answers to read.
		return oadr2b.CodeOK, "OK"
	}
	if ce.EiCreatedEvent.EventResponses == nil {
		return oadr2b.CodeOK, "OK"
	}
	code, desc := oadr2b.CodeOK, "OK"
	type answer struct{ id, opt string }
	var told []answer
	v.mu.Lock()
	st := v.stateLocked(venID)
	for _, r := range ce.EiCreatedEvent.EventResponses.Response {
		q := r.QualifiedEventID
		e := st.events[q.EventID]
		switch {
		case e == nil:
			code, desc = oadr2b.CodeInvalidID, "unknown eventID "+q.EventID
			continue
		case q.ModificationNumber != e.ev.EiEvent.Descriptor.ModificationNumber:
			code, desc = oadr2b.CodeOutOfSequence, "event "+q.EventID+": not the current modificationNumber"
			continue
		}
		opt := r.OptType
		if r.ResponseCode != "" && r.ResponseCode != oadr2b.CodeOK {
			opt = "optOut"
		}
		e.acked = int64(q.ModificationNumber)
		if !e.locked {
			e.opt = opt
		}
		told = append(told, answer{q.EventID, opt})
	}
	v.mu.Unlock()
	if v.cfg.OnEventResponse != nil {
		for _, a := range told {
			v.cfg.OnEventResponse(ctx, venID, a.id, a.opt)
		}
	}
	return code, desc
}

// createOpt takes an opt: for an event (qualifiedEventID) it fixes the
// VEN's opt state (rule 206); otherwise it is an availability schedule.
func (v *VTN) createOpt(ctx context.Context, venID string, co *oadr2b.CreateOpt) *oadr2b.SignedObject {
	answer := func(code, desc string) *oadr2b.SignedObject {
		return &oadr2b.SignedObject{CreatedOpt: &oadr2b.CreatedOpt{EiResponse: fail(code, desc, co.RequestID), OptID: co.OptID}}
	}
	switch {
	case co.OptID == "":
		return answer(oadr2b.CodeInvalidID, "optID is required")
	case co.OptType != "optIn" && co.OptType != "optOut":
		return answer(oadr2b.CodeInvalidData, "optType is optIn or optOut")
	case len(co.Target.VenID) > 0 && !slices.Contains(co.Target.VenID, venID):
		return answer(oadr2b.CodeInvalidID, "the eiTarget names another VEN")
	case co.QualifiedEventID == nil && co.Vavailability == nil:
		return answer(oadr2b.CodeInvalidData, "an opt names an event or a schedule")
	}
	eventID := ""
	if q := co.QualifiedEventID; q != nil {
		eventID = q.EventID
		v.mu.Lock()
		e := v.stateLocked(venID).events[eventID]
		v.mu.Unlock()
		if e == nil {
			return answer(oadr2b.CodeInvalidID, "unknown eventID "+eventID)
		}
	}
	if v.cfg.OnCreateOpt != nil {
		if err := v.cfg.OnCreateOpt(ctx, venID, co); err != nil {
			return answer(refusal(err, oadr2b.CodeNotAllowed))
		}
	}
	v.mu.Lock()
	st := v.stateLocked(venID)
	st.opts[co.OptID] = eventID
	if e := st.events[eventID]; e != nil {
		e.opt, e.locked = co.OptType, true
	}
	v.mu.Unlock()
	return &oadr2b.SignedObject{CreatedOpt: &oadr2b.CreatedOpt{EiResponse: ok(co.RequestID), OptID: co.OptID}}
}

// cancelOpt withdraws an opt; an unknown optID is 452 (rule 208).
func (v *VTN) cancelOpt(ctx context.Context, venID string, co *oadr2b.CancelOpt) *oadr2b.SignedObject {
	v.mu.Lock()
	st := v.stateLocked(venID)
	eventID, known := st.opts[co.OptID]
	v.mu.Unlock()
	if !known {
		return &oadr2b.SignedObject{CanceledOpt: &oadr2b.CanceledOpt{EiResponse: fail(oadr2b.CodeInvalidID, "unknown optID", co.RequestID), OptID: co.OptID}}
	}
	if v.cfg.OnCancelOpt != nil {
		if err := v.cfg.OnCancelOpt(ctx, venID, co.OptID); err != nil {
			code, desc := refusal(err, oadr2b.CodeNotAllowed)
			return &oadr2b.SignedObject{CanceledOpt: &oadr2b.CanceledOpt{EiResponse: fail(code, desc, co.RequestID), OptID: co.OptID}}
		}
	}
	v.mu.Lock()
	delete(st.opts, co.OptID)
	if e := st.events[eventID]; e != nil {
		e.locked = false
	}
	v.mu.Unlock()
	return &oadr2b.SignedObject{CanceledOpt: &oadr2b.CanceledOpt{EiResponse: ok(co.RequestID), OptID: co.OptID}}
}
