// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
	"github.com/cB-Sigma/openadr/oadr2b/vtn"
)

// A VTN that accepts every VEN, requests all of its reports and prints
// the answers to its events. A VEN registers and polls by hand here; in
// production the VTN runs behind mutual TLS (ServerTLSConfig, Serve).
func Example() {
	v := vtn.New(vtn.Config{
		VtnID:    "my-vtn",
		PollFreq: 30 * time.Second,
		OnCreatePartyRegistration: func(_ context.Context, info vtn.RegistrationInfo) (string, string, error) {
			return "ven-" + info.VenName, "", nil
		},
		OnRegisterReport: func(_ context.Context, _ string, reports []oadr2b.Report) []oadr2b.ReportRequest {
			return vtn.RequestAll(reports, time.Minute, 15*time.Minute)
		},
		OnEventResponse: func(_ context.Context, venID, eventID, optType string) {
			fmt.Println(venID, eventID, optType)
		},
	})
	defer v.Close()
	srv := httptest.NewServer(v)
	defer srv.Close()

	post := func(svc string, so oadr2b.SignedObject) *oadr2b.SignedObject {
		b, _ := oadr2b.Marshal(so)
		ans, _, err := oadr2b.PostXML(context.Background(), srv.Client(), srv.URL+oadr2b.PathBase+svc, b)
		if err != nil {
			panic(err)
		}
		out, _ := oadr2b.Unmarshal(ans)
		return out
	}
	pull := true
	reg := post(oadr2b.ServiceRegisterParty, oadr2b.SignedObject{CreatePartyRegistration: &oadr2b.CreatePartyRegistration{
		RequestID: "r1", ProfileName: "2.0b", TransportName: "simpleHttp", VenName: "kitchen", HTTPPullModel: &pull}})
	venID := reg.CreatedPartyRegistration.VenID

	_ = v.AddEvent(venID, vtn.EventSpec{ID: "peak-1", Start: time.Now(),
		Intervals: []vtn.IntervalSpec{{Duration: time.Hour, Value: 1}}}.Build())
	de := post(oadr2b.ServicePoll, oadr2b.SignedObject{Poll: &oadr2b.Poll{VenID: venID}}).DistributeEvent
	d := de.Events[0].EiEvent.Descriptor
	post(oadr2b.ServiceEvent, oadr2b.SignedObject{CreatedEvent: &oadr2b.CreatedEvent{EiCreatedEvent: oadr2b.EiCreatedEvent{
		EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK}, VenID: venID,
		EventResponses: &oadr2b.EventResponses{Response: []oadr2b.EventResponse{{ResponseCode: oadr2b.CodeOK, RequestID: de.RequestID,
			QualifiedEventID: oadr2b.QualifiedEventID{EventID: d.EventID, ModificationNumber: d.ModificationNumber}, OptType: "optIn"}}}}}})
	// Output:
	// ven-kitchen peak-1 optIn
}
