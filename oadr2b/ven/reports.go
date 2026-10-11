// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ven

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// request is one accepted report request.
type request struct {
	id, spec, name string
	rids           []string
	gran, back     time.Duration
	start, end     time.Time // end zero: no end
	nextSample     time.Time
	nextSend       time.Time
	buf            []oadr2b.Interval
}

// maxIntervals bounds the intervals of one oadrUpdateReport.
const maxIntervals = 100

// reportTick is how often the report loop looks for due work.
const reportTick = 100 * time.Millisecond

// metadata is the METADATA sent: Config.Reports with createdDateTime
// filled in.
func (v *VEN) metadata() []oadr2b.Report {
	now := oadr2b.FormatTime(time.Now())
	out := slices.Clone(v.cfg.Reports)
	for i := range out {
		if out[i].CreatedDateTime == "" {
			out[i].CreatedDateTime = now
		}
		if out[i].ReportRequestID == "" {
			out[i].ReportRequestID = "0"
		}
	}
	return out
}

// registerReports sends the METADATA (rule 309), as the answer to a
// request for it when reportRequestID is set, and takes the report
// requests that come back with oadrRegisteredReport.
func (v *VEN) registerReports(ctx context.Context, reportRequestID string) error {
	ans, err := v.Send(ctx, oadr2b.ServiceReport, oadr2b.SignedObject{RegisterReport: &oadr2b.RegisterReport{
		RequestID: newID("rr-"), Reports: v.metadata(), VenID: v.VenID(), ReportRequestID: reportRequestID}})
	if err != nil {
		return fmt.Errorf("register report: %w", err)
	}
	if c, msg := codeOf(ans); c != oadr2b.CodeOK {
		return fmt.Errorf("register report: %s %s", c, msg)
	}
	if ans.RegisteredReport == nil || len(ans.RegisteredReport.ReportRequests) == 0 {
		return nil
	}
	// Report requests in the answer (rule 344) are answered with
	// oadrCreatedReport like those of oadrCreateReport.
	reply, after := v.acceptReports(ans.RegisteredReport.EiResponse.RequestID, ans.RegisteredReport.ReportRequests)
	if _, err := v.Send(ctx, oadr2b.ServiceReport, *reply); err != nil {
		return fmt.Errorf("created report: %w", err)
	}
	return after(ctx)
}

// offered is the report with this reportSpecifierID: its name without
// METADATA_ and its rIDs and finest sampling period.
func (v *VEN) offered(spec string) (name string, rids []string, minPeriod time.Duration, found bool) {
	for _, rep := range v.cfg.Reports {
		if rep.ReportSpecifierID != spec {
			continue
		}
		for _, d := range rep.Descriptions {
			rids = append(rids, d.RID)
			if d.SamplingRate != nil {
				if m, err := oadr2b.ParseDuration(d.SamplingRate.MinPeriod); err == nil && m > minPeriod {
					minPeriod = m
				}
			}
		}
		return strings.TrimPrefix(rep.ReportName, "METADATA_"), rids, minPeriod, true
	}
	return "", nil, 0, false
}

// takeRequest checks one report request and makes a schedule of it.
func (v *VEN) takeRequest(rq oadr2b.ReportRequest, now time.Time) (*request, string, error) {
	spec := rq.ReportSpecifier
	if spec.ReportSpecifierID == "METADATA" {
		return &request{id: rq.ReportRequestID, spec: "METADATA"}, oadr2b.CodeOK, nil
	}
	name, rids, minP, found := v.offered(spec.ReportSpecifierID)
	if !found {
		return nil, oadr2b.CodeInvalidID, fmt.Errorf("unknown reportSpecifierID %s", spec.ReportSpecifierID)
	}
	r := &request{id: rq.ReportRequestID, spec: spec.ReportSpecifierID, name: name, start: now}
	for _, p := range spec.SpecifierPayloads {
		if !slices.Contains(rids, p.RID) {
			// Rules 300 and 304: only data points of the METADATA.
			return nil, oadr2b.CodeInvalidID, fmt.Errorf("report %s has no rID %s", spec.ReportSpecifierID, p.RID)
		}
		r.rids = append(r.rids, p.RID)
	}
	if len(r.rids) == 0 {
		r.rids = rids
	}
	var err error
	if spec.Granularity.Duration != "" {
		if r.gran, err = oadr2b.ParseDuration(spec.Granularity.Duration); err != nil {
			return nil, oadr2b.CodeInvalidData, fmt.Errorf("granularity: %w", err)
		}
	}
	if spec.ReportBackDuration.Duration != "" {
		if r.back, err = oadr2b.ParseDuration(spec.ReportBackDuration.Duration); err != nil {
			return nil, oadr2b.CodeInvalidData, fmt.Errorf("reportBackDuration: %w", err)
		}
	}
	if ri := spec.ReportInterval; ri != nil {
		if t, err := oadr2b.ParseTime(ri.Properties.DtStart.DateTime); err == nil {
			r.start = t
		}
		if d, err := oadr2b.ParseDuration(ri.Properties.Duration.Duration); err == nil && d > 0 {
			r.end = r.start.Add(d)
		}
	}
	// Rule 317: no finer than the data points' oadrMinPeriod.
	if r.gran > 0 && r.gran < minP {
		r.gran = minP
	}
	if r.gran == 0 {
		r.gran = max(r.back, minP, time.Second)
	}
	if r.back > 0 && r.back < r.gran {
		r.back = r.gran
	}
	begin := r.start
	if begin.Before(now) {
		begin = now
	}
	r.nextSample = begin.Add(r.gran)
	r.nextSend = begin.Add(r.back)
	return r, oadr2b.CodeOK, nil
}

// acceptReports takes report requests (from oadrCreateReport or with
// oadrRegisteredReport) and gives the oadrCreatedReport answer with the
// periodic requests pending, and what to send after it: one-shot
// reports and any METADATA asked for.
func (v *VEN) acceptReports(requestID string, reqs []oadr2b.ReportRequest) (*oadr2b.SignedObject, func(context.Context) error) {
	now := time.Now()
	var accepted []*request
	code, desc := oadr2b.CodeOK, "OK"
	for _, rq := range reqs {
		r, c, err := v.takeRequest(rq, now)
		if err != nil {
			code, desc = c, err.Error()
			continue
		}
		accepted = append(accepted, r)
	}
	v.mu.Lock()
	for _, r := range accepted {
		if r.spec != "METADATA" && r.back > 0 {
			v.requests[r.id] = r
		}
	}
	pending := make([]string, 0, len(v.requests))
	for id := range v.requests {
		pending = append(pending, id)
	}
	v.mu.Unlock()
	slices.Sort(pending)
	answer := &oadr2b.SignedObject{CreatedReport: &oadr2b.CreatedReport{EiResponse: fail(code, desc, requestID),
		PendingReports: oadr2b.PendingReports{ReportRequestID: pending}, VenID: v.VenID()}}
	return answer, func(ctx context.Context) error {
		for _, r := range accepted {
			var err error
			switch {
			case r.spec == "METADATA":
				err = v.registerReports(ctx, r.id)
			case r.back == 0:
				// Rule 324: a one-shot request has one report.
				v.sample(ctx, r, time.Now())
				err = v.sendReport(ctx, r)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// cancelReports answers oadrCancelReport (rules 336 and 345) and gives
// the final reports to send after the answer.
func (v *VEN) cancelReports(cr *oadr2b.CancelReport) (*oadr2b.SignedObject, func(context.Context) error) {
	code, desc := oadr2b.CodeOK, "OK"
	var final []*request
	v.mu.Lock()
	for _, id := range cr.ReportRequestID {
		r := v.requests[id]
		if r == nil {
			code, desc = oadr2b.CodeInvalidID, "unknown reportRequestID "+id
			continue
		}
		delete(v.requests, id)
		if cr.ReportToFollow {
			final = append(final, r)
		}
	}
	pending := make([]string, 0, len(v.requests))
	for id := range v.requests {
		pending = append(pending, id)
	}
	v.mu.Unlock()
	slices.Sort(pending)
	answer := &oadr2b.SignedObject{CanceledReport: &oadr2b.CanceledReport{EiResponse: fail(code, desc, cr.RequestID),
		PendingReports: oadr2b.PendingReports{ReportRequestID: pending}, VenID: v.VenID()}}
	return answer, func(ctx context.Context) error {
		for _, r := range final {
			v.sample(ctx, r, time.Now())
			if err := v.sendReport(ctx, r); err != nil {
				return err
			}
		}
		return nil
	}
}

// sample reads the request's data points into one interval per data
// point ending at at. Each payload has an interval of its own, which
// every reader handles (some read only one payload per interval).
func (v *VEN) sample(ctx context.Context, r *request, at time.Time) {
	start := at.Add(-r.gran)
	for _, rid := range r.rids {
		p, found := oadr2b.ReportPayload{}, false
		if v.cfg.ReadData != nil {
			p, found = v.cfg.ReadData(ctx, r.spec, rid, at)
		}
		if !found {
			// Rule 318: a placeholder marked bad.
			p = oadr2b.ReportPayload{PayloadFloat: &oadr2b.PayloadFloat{}, DataQuality: "Quality Bad - Non Specific"}
		}
		p.RID = rid
		iv := oadr2b.Interval{DtStart: &oadr2b.DtStart{DateTime: oadr2b.FormatTime(start)},
			Duration: &oadr2b.DurationProp{Duration: oadr2b.FormatDuration(r.gran)}, ReportPayload: []oadr2b.ReportPayload{p}}
		v.mu.Lock()
		r.buf = append(r.buf, iv)
		if n := len(r.buf); n > maxIntervals {
			r.buf = r.buf[n-maxIntervals:]
		}
		v.mu.Unlock()
	}
}

// sendReport sends what the request has collected in one
// oadrUpdateReport; the VTN may cancel the request in its answer (rule
// 328).
func (v *VEN) sendReport(ctx context.Context, r *request) error {
	v.mu.Lock()
	ivs := r.buf
	r.buf = nil
	v.mu.Unlock()
	if len(ivs) == 0 {
		return nil
	}
	first, _ := oadr2b.ParseTime(ivs[0].DtStart.DateTime)
	last, _ := oadr2b.ParseTime(ivs[len(ivs)-1].DtStart.DateTime)
	rep := oadr2b.Report{DtStart: &oadr2b.DtStart{DateTime: oadr2b.FormatTime(first)},
		Duration:  &oadr2b.DurationProp{Duration: oadr2b.FormatDuration(last.Add(r.gran).Sub(first))},
		Intervals: &oadr2b.Intervals{Interval: ivs}, ReportRequestID: r.id, ReportSpecifierID: r.spec, ReportName: r.name,
		CreatedDateTime: oadr2b.FormatTime(time.Now())}
	ans, err := v.Send(ctx, oadr2b.ServiceReport, oadr2b.SignedObject{UpdateReport: &oadr2b.UpdateReport{RequestID: newID("ur-"),
		Reports: []oadr2b.Report{rep}, VenID: v.VenID()}})
	if err != nil {
		return err
	}
	if ans != nil && ans.UpdatedReport != nil && ans.UpdatedReport.CancelReport != nil {
		v.mu.Lock()
		for _, id := range ans.UpdatedReport.CancelReport.ReportRequestID {
			delete(v.requests, id)
		}
		v.mu.Unlock()
	}
	if c, msg := codeOf(ans); ans != nil && c != oadr2b.CodeOK {
		return fmt.Errorf("update report: %s %s", c, msg)
	}
	return nil
}

// reportLoop samples and sends periodic reports when they are due.
func (v *VEN) reportLoop(ctx context.Context) {
	t := time.NewTicker(reportTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := time.Now()
		var due, sample []*request
		v.mu.Lock()
		if v.regID == "" {
			v.mu.Unlock()
			continue
		}
		for id, r := range v.requests {
			if !r.end.IsZero() && now.After(r.end) {
				delete(v.requests, id) // rule 325: the period is over
				continue
			}
			if !now.Before(r.nextSample) {
				sample = append(sample, r)
				r.nextSample = r.nextSample.Add(r.gran)
				if r.nextSample.Before(now) {
					r.nextSample = now.Add(r.gran)
				}
			}
			if !now.Before(r.nextSend) {
				due = append(due, r)
				r.nextSend = r.nextSend.Add(r.back)
				if r.nextSend.Before(now) {
					r.nextSend = now.Add(r.back)
				}
			}
		}
		v.mu.Unlock()
		for _, r := range sample {
			v.sample(ctx, r, now)
		}
		for _, r := range due {
			if err := v.sendReport(ctx, r); err != nil && ctx.Err() == nil {
				v.log.Warn("OpenADR VEN: sending a report failed", "reportRequestID", r.id, "error", err)
			}
		}
	}
}
