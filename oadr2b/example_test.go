// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package oadr2b_test

import (
	"fmt"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// A VEN's oadrPoll, written as a payload and read back.
func Example() {
	b, err := oadr2b.Marshal(oadr2b.SignedObject{Poll: &oadr2b.Poll{VenID: "ven-1"}})
	if err != nil {
		panic(err)
	}
	so, err := oadr2b.Unmarshal(b)
	if err != nil {
		panic(err)
	}
	fmt.Println(oadr2b.MessageName(so), so.Poll.VenID)
	fmt.Println(oadr2b.FormatDuration(90 * time.Minute))
	// Output:
	// oadrPoll ven-1
	// PT1H30M
}
