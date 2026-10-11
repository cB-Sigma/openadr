// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package oadr2b_test

import (
	"bytes"
	"testing"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// Regression tests for differences found by running this library
// against other implementations (the interop module).

// A payload read with an Id on oadrSignedObject (as OpenLEADR writes
// every message) is written back with oadr:Id: the 2.0b schema qualifies
// local attributes, and OpenLEADR's schema check refused the unqualified
// Id that Marshal wrote before v0.1.0. An unqualified Id is still read.
func TestMarshalQualifiesSignedObjectID(t *testing.T) {
	for _, attr := range []string{`oadr:Id="oadrSignedObject"`, `Id="oadrSignedObject"`} {
		in := []byte(`<?xml version="1.0" encoding="utf-8"?>
<oadr:oadrPayload xmlns:oadr="http://openadr.org/oadr-2.0b/2012/07">
<oadr:oadrSignedObject xmlns:oadr="http://openadr.org/oadr-2.0b/2012/07" ` + attr + `>
  <oadr:oadrPoll ei:schemaVersion="2.0b" xmlns:ei="http://docs.oasis-open.org/ns/energyinterop/201110">
    <ei:venID>ven-1</ei:venID>
  </oadr:oadrPoll>
</oadr:oadrSignedObject>
</oadr:oadrPayload>`)
		so, err := oadr2b.Unmarshal(in)
		if err != nil {
			t.Fatal(err)
		}
		if so.ID != "oadrSignedObject" {
			t.Fatalf("%s read as ID %q", attr, so.ID)
		}
		out, err := oadr2b.Marshal(*so)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(out, []byte(`<oadr:oadrSignedObject oadr:Id="oadrSignedObject">`)) || bytes.Contains(out, []byte(` Id="`)) {
			t.Fatalf("written back from %s:\n%s", attr, out)
		}
		again, err := oadr2b.Unmarshal(out)
		if err != nil || again.ID != "oadrSignedObject" || again.Poll == nil || again.Poll.VenID != "ven-1" {
			t.Fatalf("read again: %+v, %v", again, err)
		}
	}
	// Without an Id nothing is added, and an Id needing escapes is escaped.
	out, err := oadr2b.Marshal(oadr2b.SignedObject{Poll: &oadr2b.Poll{VenID: "v"}})
	if err != nil || bytes.Contains(out, []byte("Id=")) {
		t.Fatalf("no Id: %s, %v", out, err)
	}
	out, err = oadr2b.Marshal(oadr2b.SignedObject{ID: `a"<b`, Poll: &oadr2b.Poll{VenID: "v"}})
	if err != nil || !bytes.Contains(out, []byte(`oadr:Id="a&#34;&lt;b"`)) {
		t.Fatalf("escaped Id: %s, %v", out, err)
	}
}
