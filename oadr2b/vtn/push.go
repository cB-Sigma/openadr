// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

// Push delivery (section 9.1.1.1): for a VEN registered with
// oadrHttpPullModel false the VTN posts what a polling VEN would get from
// oadrPoll to the matching service under the VEN's oadrTransportAddress
// and reads the VEN's answer from the HTTP response. A message leaves the
// queue once the VEN accepted it; failures are retried with a back-off.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// kick starts delivering what waits for a push VEN, unless a delivery is
// running.
func (v *VTN) kick(venID string) {
	v.mu.Lock()
	st := v.states[venID]
	if v.closed || st == nil || st.reg == nil || !st.reg.Push || st.pushing {
		v.mu.Unlock()
		return
	}
	st.pushing = true
	v.wg.Add(1)
	v.mu.Unlock()
	go func() {
		defer v.wg.Done()
		v.flush(venID)
	}()
}

// flush pushes until nothing waits or a push fails.
func (v *VTN) flush(venID string) {
	var err error
	more := true
	for more && err == nil && v.ctx.Err() == nil {
		more, err = v.pushNext(venID)
	}
	v.mu.Lock()
	st := v.states[venID]
	if st == nil {
		v.mu.Unlock()
		return
	}
	st.pushing = false
	if err == nil || v.closed || st.reg == nil {
		if err == nil {
			st.pushFails = 0
		}
		v.mu.Unlock()
		return
	}
	st.pushFails++
	wait := v.cfg.PushRetry
	for i := 1; i < st.pushFails && wait < 5*time.Minute; i++ {
		wait *= 2
	}
	wait = min(wait, 5*time.Minute)
	if st.pushTimer != nil {
		st.pushTimer.Stop()
	}
	st.pushTimer = time.AfterFunc(wait, func() { v.kick(venID) })
	v.mu.Unlock()
	v.log.Warn("OpenADR VTN: push failed; trying again", "ven", venID, "error", err, "retry", wait)
	if v.cfg.OnPushError != nil {
		v.cfg.OnPushError(venID, err)
	}
}

// pushURL joins a VEN's transport address and a service: the address may
// be the VEN's base URL, end in the simple-HTTP path or name the service.
func pushURL(addr, svc string) string {
	u := strings.TrimRight(addr, "/")
	if strings.HasSuffix(u, "/"+svc) {
		return u
	}
	if strings.HasSuffix(u, strings.TrimRight(oadr2b.PathBase, "/")) {
		return u + "/" + svc
	}
	return u + oadr2b.PathBase + svc
}

// serviceOf is the VEN endpoint a VTN message goes to.
func serviceOf(so *oadr2b.SignedObject) string {
	switch {
	case so.RegisterReport != nil, so.CreateReport != nil, so.CancelReport != nil, so.UpdateReport != nil:
		return oadr2b.ServiceReport
	case so.CancelPartyRegistration != nil, so.RequestReregistration != nil:
		return oadr2b.ServiceRegisterParty
	}
	return oadr2b.ServiceEvent
}

// pushNext delivers one waiting message; more says whether another waits.
func (v *VTN) pushNext(venID string) (more bool, err error) {
	ctx := v.ctx
	v.mu.Lock()
	st := v.states[venID]
	if st == nil || st.reg == nil || !st.reg.Push {
		v.mu.Unlock()
		return false, nil
	}
	var msg oadr2b.SignedObject
	fromQueue := false
	gen := st.eventsGen
	switch {
	case len(st.queue) > 0:
		msg, fromQueue = st.queue[0], true
	case st.eventsDirty:
		msg = oadr2b.SignedObject{DistributeEvent: v.distributionLocked(venID, st, newID("req-"), 0, time.Now())}
		// Rule 40 asks for eiResponse only in answers to requests.
		msg.DistributeEvent.EiResponse = nil
	default:
		v.mu.Unlock()
		return false, nil
	}
	reg := *st.reg
	v.mu.Unlock()

	b, err := v.encode(msg)
	if err != nil {
		return false, err
	}
	body, _, err := oadr2b.PostXML(ctx, v.cfg.PushClient, pushURL(reg.TransportAddress, serviceOf(&msg)), b)
	if err != nil {
		return false, err
	}
	delivered := func() bool {
		v.mu.Lock()
		if fromQueue && len(st.queue) > 0 {
			st.queue = st.queue[1:]
		} else if !fromQueue && st.eventsGen == gen {
			st.eventsDirty = false
		}
		more := st.reg != nil && (len(st.queue) > 0 || st.eventsDirty)
		v.mu.Unlock()
		if msg.CancelPartyRegistration != nil {
			v.unregister(ctx, reg, true)
			return false
		}
		return more
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return delivered(), nil // a transport-level acknowledgement only
	}
	if v.cfg.Validate != nil {
		if err := v.cfg.Validate(body); err != nil {
			return false, fmt.Errorf("the VEN's answer: %w", err)
		}
	}
	if v.cfg.RequireSignatures {
		// The VEN's push server certificate need not be its client
		// certificate; the signature must be the registered VEN's.
		if _, err := v.checkSignature(body, "", &reg); err != nil {
			return false, fmt.Errorf("the VEN's answer: XML signature: %w", err)
		}
	}
	so, err := oadr2b.Unmarshal(body)
	if err != nil {
		return false, fmt.Errorf("the VEN's answer: %w", err)
	}
	if claimed := messageVenID(so); claimed != "" && claimed != venID {
		return false, errors.New("the VEN answered for another venID")
	}
	switch {
	case so.CreatedEvent != nil:
		more = delivered()
		v.createdEvent(ctx, venID, so.CreatedEvent)
		return more, nil
	case so.CreatedReport != nil:
		more = delivered()
		if v.cfg.OnCreatedReport != nil {
			v.cfg.OnCreatedReport(ctx, venID, so.CreatedReport.PendingReports.ReportRequestID)
		}
		return more, nil
	case so.RegisteredReport != nil, so.CanceledReport != nil, so.CanceledPartyRegistration != nil, so.UpdatedReport != nil:
		return delivered(), nil
	case so.Response != nil:
		if c := so.Response.EiResponse.ResponseCode; c != "" && c != oadr2b.CodeOK {
			return false, fmt.Errorf("the VEN answered %s %s", c, so.Response.EiResponse.ResponseDescription)
		}
		return delivered(), nil
	}
	return false, fmt.Errorf("the VEN answered %s", oadr2b.MessageName(so))
}
