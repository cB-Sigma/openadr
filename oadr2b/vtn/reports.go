// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// NewReportRequest is a request for the data points rids of the report
// reportSpecifierID that a VEN offers, with granularity and
// reportBackDuration (a zero reportBack asks for one report). The
// interval starts now and has no end. Pass "METADATA" as the specifier to
// ask for the VEN's METADATA again.
func NewReportRequest(specifierID string, rids []string, granularity, reportBack time.Duration) oadr2b.ReportRequest {
	if specifierID == "METADATA" && len(rids) == 0 {
		// Rule 308: rID 0 when asking for METADATA.
		rids = []string{"0"}
	}
	sp := make([]oadr2b.SpecifierPayload, len(rids))
	for i, r := range rids {
		sp[i] = oadr2b.SpecifierPayload{RID: r, ReadingType: "x-notApplicable"}
	}
	return oadr2b.ReportRequest{ReportRequestID: newID("rr-"), ReportSpecifier: oadr2b.ReportSpecifier{
		ReportSpecifierID: specifierID, Granularity: oadr2b.DurationProp{Duration: oadr2b.FormatDuration(granularity)},
		ReportBackDuration: oadr2b.DurationProp{Duration: oadr2b.FormatDuration(reportBack)},
		ReportInterval: &oadr2b.ReportInterval{Properties: oadr2b.Properties{DtStart: oadr2b.DtStart{DateTime: oadr2b.FormatTime(time.Now())},
			Duration: oadr2b.DurationProp{Duration: "PT0S"}}},
		SpecifierPayloads: sp}}
}

// RequestAll requests every report of a METADATA list except history
// reports, with every data point: granularity no finer than any data
// point's oadrMinPeriod (rule 317) and reportBackDuration no shorter than
// the granularity. Use it from OnRegisterReport.
func RequestAll(reports []oadr2b.Report, granularity, reportBack time.Duration) []oadr2b.ReportRequest {
	var out []oadr2b.ReportRequest
	for _, rep := range reports {
		if strings.HasPrefix(rep.ReportName, "METADATA_HISTORY") {
			continue
		}
		gran := granularity
		var rids []string
		for _, d := range rep.Descriptions {
			if d.RID == "" {
				continue
			}
			rids = append(rids, d.RID)
			if d.SamplingRate != nil {
				if m, err := oadr2b.ParseDuration(d.SamplingRate.MinPeriod); err == nil && m > gran {
					gran = m
				}
			}
		}
		if len(rids) == 0 {
			continue
		}
		out = append(out, NewReportRequest(rep.ReportSpecifierID, rids, gran, max(reportBack, gran)))
	}
	return out
}

// registerReport takes a VEN's METADATA: it replaces the previous one
// and ends every earlier request (rule 306); the answer carries the
// requests OnRegisterReport returns.
func (v *VTN) registerReport(ctx context.Context, venID string, rr *oadr2b.RegisterReport) *oadr2b.SignedObject {
	answer := func(r oadr2b.EiResponse, reqs []oadr2b.ReportRequest) *oadr2b.SignedObject {
		return &oadr2b.SignedObject{RegisteredReport: &oadr2b.RegisteredReport{EiResponse: r, ReportRequests: reqs, VenID: venID}}
	}
	seen := map[string]bool{}
	for _, rep := range rr.Reports {
		// Rule 308: reportSpecifierIDs are unique in a METADATA report.
		if rep.ReportSpecifierID == "" || seen[rep.ReportSpecifierID] {
			return answer(fail(oadr2b.CodeInvalidID, "reportSpecifierID missing or used twice", rr.RequestID), nil)
		}
		seen[rep.ReportSpecifierID] = true
	}
	v.mu.Lock()
	st := v.stateLocked(venID)
	st.meta = slices.Clone(rr.Reports)
	for id := range st.requests {
		st.cancelled[id] = true
	}
	st.requests, st.final = map[string]string{}, map[string]bool{}
	v.mu.Unlock()
	var reqs []oadr2b.ReportRequest
	if v.cfg.OnRegisterReport != nil {
		reqs = v.cfg.OnRegisterReport(ctx, venID, rr.Reports)
	}
	v.mu.Lock()
	for _, q := range reqs {
		if q.ReportSpecifier.ReportSpecifierID != "METADATA" {
			st.requests[q.ReportRequestID] = q.ReportSpecifier.ReportSpecifierID
			delete(st.cancelled, q.ReportRequestID)
		}
	}
	v.mu.Unlock()
	return answer(ok(rr.RequestID), reqs)
}

// venCreateReport answers a VEN's request for the VTN's reports: METADATA
// is sent as oadrRegisterReport carrying the request's reportRequestID
// (rules 301 and 311); this VTN keeps no report data of its own, so
// other requests are 452.
func (v *VTN) venCreateReport(venID string, cr *oadr2b.CreateReport) *oadr2b.SignedObject {
	var meta []string
	for _, r := range cr.ReportRequests {
		if r.ReportSpecifier.ReportSpecifierID != "METADATA" {
			return &oadr2b.SignedObject{CreatedReport: &oadr2b.CreatedReport{EiResponse: fail(oadr2b.CodeInvalidID,
				"this VTN offers no report "+r.ReportSpecifier.ReportSpecifierID, cr.RequestID), VenID: venID}}
		}
		meta = append(meta, r.ReportRequestID)
	}
	for _, id := range meta {
		_ = v.enqueue(venID, oadr2b.SignedObject{RegisterReport: &oadr2b.RegisterReport{RequestID: newID("req-"), Reports: v.cfg.Metadata,
			VenID: venID, ReportRequestID: id}})
	}
	return &oadr2b.SignedObject{CreatedReport: &oadr2b.CreatedReport{EiResponse: ok(cr.RequestID), VenID: venID}}
}

// venCancelReport answers a VEN's cancellation of requests for the VTN's
// reports, of which there are none (rule 336: an unknown ID is 452).
func (v *VTN) venCancelReport(venID string, cr *oadr2b.CancelReport) *oadr2b.SignedObject {
	code, desc := oadr2b.CodeOK, "OK"
	if len(cr.ReportRequestID) > 0 {
		code, desc = oadr2b.CodeInvalidID, "no such report request "+cr.ReportRequestID[0]
	}
	return &oadr2b.SignedObject{CanceledReport: &oadr2b.CanceledReport{EiResponse: fail(code, desc, cr.RequestID), VenID: venID}}
}

// updateReport takes report data. A report for a request the VTN
// cancelled is answered with the cancellation again (rule 335); one for
// an unknown request is 452 (rule 304); the others go to OnUpdateReport.
func (v *VTN) updateReport(ctx context.Context, venID string, ur *oadr2b.UpdateReport) *oadr2b.SignedObject {
	var again []string
	var accepted []oadr2b.Report
	code, desc := oadr2b.CodeOK, "OK"
	v.mu.Lock()
	st := v.stateLocked(venID)
	for _, rep := range ur.Reports {
		id := rep.ReportRequestID
		switch {
		case st.cancelled[id]:
			again = append(again, id)
		case st.requests[id] == "":
			code, desc = oadr2b.CodeInvalidID, "unknown reportRequestID "+id
		default:
			accepted = append(accepted, rep)
			if st.final[id] {
				// The report that was to follow the cancellation.
				delete(st.final, id)
				delete(st.requests, id)
				st.cancelled[id] = true
			}
		}
	}
	v.mu.Unlock()
	if len(accepted) > 0 && v.cfg.OnUpdateReport != nil {
		if err := v.cfg.OnUpdateReport(ctx, venID, accepted); err != nil {
			code, desc = refusal(err, oadr2b.CodeInvalidData)
		}
	}
	out := &oadr2b.UpdatedReport{EiResponse: fail(code, desc, ur.RequestID), VenID: venID}
	if len(again) > 0 {
		out.CancelReport = &oadr2b.CancelReport{RequestID: newID("cr-"), ReportRequestID: again, VenID: venID}
	}
	return &oadr2b.SignedObject{UpdatedReport: out}
}

// Metadata is the VEN's last METADATA report list.
func (v *VTN) Metadata(venID string) []oadr2b.Report {
	v.mu.Lock()
	defer v.mu.Unlock()
	if st := v.states[venID]; st != nil {
		return slices.Clone(st.meta)
	}
	return nil
}

// ReportRequests lists the VEN's active report requests:
// reportRequestID → reportSpecifierID.
func (v *VTN) ReportRequests(venID string) map[string]string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := map[string]string{}
	if st := v.states[venID]; st != nil {
		for k, x := range st.requests {
			out[k] = x
		}
	}
	return out
}

// RequestReport sends oadrCreateReport with the requests. Each must name
// a report of the VEN's METADATA and only its data points (rule 300), or
// METADATA itself.
func (v *VTN) RequestReport(venID string, reqs ...oadr2b.ReportRequest) error {
	if _, err := v.registered(venID); err != nil {
		return err
	}
	v.mu.Lock()
	st := v.stateLocked(venID)
	for _, q := range reqs {
		spec := q.ReportSpecifier.ReportSpecifierID
		if spec == "METADATA" {
			continue
		}
		i := slices.IndexFunc(st.meta, func(r oadr2b.Report) bool { return r.ReportSpecifierID == spec })
		if i < 0 {
			v.mu.Unlock()
			return fmt.Errorf("VEN %s offers no report %s", venID, spec)
		}
		for _, p := range q.ReportSpecifier.SpecifierPayloads {
			if !slices.ContainsFunc(st.meta[i].Descriptions, func(d oadr2b.ReportDescription) bool { return d.RID == p.RID }) {
				v.mu.Unlock()
				return fmt.Errorf("report %s has no data point %s", spec, p.RID)
			}
		}
	}
	for _, q := range reqs {
		if q.ReportSpecifier.ReportSpecifierID != "METADATA" {
			st.requests[q.ReportRequestID] = q.ReportSpecifier.ReportSpecifierID
		}
	}
	v.mu.Unlock()
	return v.enqueue(venID, oadr2b.SignedObject{CreateReport: &oadr2b.CreateReport{RequestID: newID("req-"), ReportRequests: reqs, VenID: venID}})
}

// CancelReport sends oadrCancelReport for active requests. With
// reportToFollow the VEN sends one last report, which is still taken.
func (v *VTN) CancelReport(venID string, reportRequestIDs []string, reportToFollow bool) error {
	if _, err := v.registered(venID); err != nil {
		return err
	}
	v.mu.Lock()
	st := v.stateLocked(venID)
	for _, id := range reportRequestIDs {
		if st.requests[id] == "" {
			v.mu.Unlock()
			return fmt.Errorf("no active report request %s", id)
		}
	}
	for _, id := range reportRequestIDs {
		if reportToFollow {
			st.final[id] = true
		} else {
			delete(st.requests, id)
			st.cancelled[id] = true
		}
	}
	v.mu.Unlock()
	return v.enqueue(venID, oadr2b.SignedObject{CancelReport: &oadr2b.CancelReport{RequestID: newID("req-"),
		ReportRequestID: slices.Clone(reportRequestIDs), ReportToFollow: reportToFollow, VenID: venID}})
}
