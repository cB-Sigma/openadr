// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package oadr3_test

import (
	"fmt"

	"github.com/cB-Sigma/openadr/oadr3"
)

// An event's time span, worked out from its intervalPeriod.
func ExampleEventWindow() {
	ev := oadr3.Object{
		"objectType":     oadr3.TypeEvent,
		"intervalPeriod": map[string]any{"start": "2026-10-06T10:00:00Z", "duration": "PT2H"},
		"intervals":      []any{map[string]any{"id": 0.0}},
	}
	w := oadr3.EventWindow(ev)
	fmt.Println(w.Start.Format("15:04"), w.End.Format("15:04"), w.Open)
	d, _, _ := oadr3.ParseDuration("P1DT2H")
	_, infinite, _ := oadr3.ParseDuration("P9999Y")
	fmt.Println(d, infinite)
	// Output:
	// 10:00 12:00 false
	// 26h0m0s true
}
