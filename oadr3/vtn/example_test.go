// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/cB-Sigma/openadr/oadr3"
	"github.com/cB-Sigma/openadr/oadr3/vtn"
)

// A VTN with one business-logic and one VEN client: business logic
// publishes a targeted event in the same process; the VEN enrols over the
// API, is granted the target, and reads the event.
func Example() {
	v, err := vtn.New(vtn.Config{
		BasePath: "/openadr3/3.1.0",
		Clients: []vtn.Client{
			{ClientID: "utility", Secret: "demo-secret-1", Role: vtn.RoleBL},
			{ClientID: "site-7", Secret: "demo-secret-2", Role: vtn.RoleVEN},
		},
		OnChange: func(c vtn.Change) {},
	})
	if err != nil {
		panic(err)
	}
	defer v.Close()
	srv := httptest.NewServer(v) // or http.ListenAndServeTLS(addr, cert, key, v)
	defer srv.Close()
	base := srv.URL + "/openadr3/3.1.0"
	v.SetPublicURL(base)
	ctx := context.Background()

	prog, _ := v.Create(ctx, oadr3.TypeProgram, oadr3.Object{"programName": "time-of-use"})
	_, _ = v.Create(ctx, oadr3.TypeEvent, oadr3.Object{"programID": prog["id"], "eventName": "evening-peak",
		"targets":   []string{"feeder-12"},
		"intervals": []any{map[string]any{"id": 0, "payloads": []any{map[string]any{"type": "PRICE", "values": []any{0.31}}}}}})

	ven := oadr3.NewClient(oadr3.ClientConfig{BaseURL: base, ClientID: "site-7", Secret: "demo-secret-2"})
	var me oadr3.Object
	_, _ = ven.Do(ctx, http.MethodPost, "/vens", nil, oadr3.Object{"objectType": "VEN_VEN_REQUEST", "venName": "site-7"}, &me)
	_, _ = v.Update(ctx, oadr3.TypeVEN, oadr3.Str(me, "id"), oadr3.Object{"venName": "site-7", "clientID": "site-7", "targets": []string{"feeder-12"}})

	events, _ := ven.All(ctx, "/events", url.Values{"targets": {"feeder-12"}})
	for _, e := range events {
		fmt.Println(e["eventName"], e["targets"])
	}
	// Output: evening-peak [feeder-12]
}
