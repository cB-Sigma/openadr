// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ven_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
	"github.com/cB-Sigma/openadr/oadr2b/ven"
	"github.com/cB-Sigma/openadr/oadr2b/vtn"
)

// A VEN that opts in to every event and reports its power, here against
// this module's VTN in the same process.
func Example() {
	got := make(chan string, 1)
	v := vtn.New(vtn.Config{OnEventResponse: func(_ context.Context, _, eventID, optType string) {
		select {
		case got <- eventID + " " + optType:
		default:
		}
	}})
	defer v.Close()
	srv := httptest.NewServer(v)
	defer srv.Close()

	vn, err := ven.New(ven.Config{
		VTNURL:   srv.URL,
		VenName:  "kitchen",
		PollFreq: 200 * time.Millisecond, // normally the VTN's choice
		Reports: []oadr2b.Report{{ReportSpecifierID: "usage", ReportName: "METADATA_TELEMETRY_USAGE",
			Descriptions: []oadr2b.ReportDescription{{RID: "power", ReportType: "usage", ReadingType: "Direct Read",
				SamplingRate: &oadr2b.SamplingRate{MinPeriod: "PT1M", MaxPeriod: "PT1H"},
				ItemBase:     &oadr2b.ItemBase{XMLName: oadr2b.XMLName(oadr2b.NSPower, "powerReal"), ItemDescription: "RealPower", ItemUnits: "W"}}}}},
		OnEvent: func(_ context.Context, ev oadr2b.OadrEvent) string {
			return "optIn"
		},
		ReadData: func(_ context.Context, _, _ string, _ time.Time) (oadr2b.ReportPayload, bool) {
			return oadr2b.ReportPayload{PayloadFloat: &oadr2b.PayloadFloat{Value: 640}}, true
		},
	})
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- vn.Run(ctx) }()
	for vn.RegistrationID() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	_ = v.AddEvent(vn.VenID(), vtn.EventSpec{ID: "peak-1", Start: time.Now(),
		Intervals: []vtn.IntervalSpec{{Duration: time.Hour, Value: 1}}}.Build())
	fmt.Println(<-got)
	cancel()
	<-done
	// Output:
	// peak-1 optIn
}
