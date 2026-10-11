// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// selfSigned makes a throw-away certificate and key (PEM) for signing.
func selfSigned(t *testing.T, key crypto.Signer) (tls.Certificate, []byte, []byte) {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "openadr interop"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c, certPEM, keyPEM
}

func ecKey(t *testing.T) crypto.Signer {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaKey(t *testing.T) crypto.Signer {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ourMessages is one message of every 2.0b type, as this library writes
// them.
func ourMessages() map[string]oadr2b.SignedObject {
	now := time.Now()
	ts := oadr2b.FormatTime(now)
	ok := oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK, ResponseDescription: "OK", RequestID: "req-1"}
	pull := true
	profiles := oadr2b.Profiles{Profile: []oadr2b.Profile{{Name: oadr2b.ProfileName, Transports: oadr2b.Transports{Transport: []oadr2b.Transport{{Name: oadr2b.TransportName}}}}}}
	start := &oadr2b.DtStart{DateTime: ts}
	min1 := &oadr2b.DurationProp{Duration: "PT1M"}
	src := &oadr2b.Target{ResourceID: []string{"device-1"}}
	rate := &oadr2b.SamplingRate{MinPeriod: "PT10S", MaxPeriod: "PT5M"}
	event := oadr2b.OadrEvent{ResponseRequired: "always", EiEvent: oadr2b.EiEvent{
		Descriptor: oadr2b.EventDescriptor{EventID: "ev-1", ModificationNumber: 2, MarketContext: oadr2b.MarketContext{MarketContext: "http://sigma.test/mc"},
			CreatedDateTime: ts, EventStatus: "active"},
		ActivePeriod: oadr2b.ActivePeriod{Properties: oadr2b.Properties{DtStart: oadr2b.DtStart{DateTime: ts}, Duration: oadr2b.DurationProp{Duration: "PT1H"}},
			Components: oadr2b.Components{Nil: "true"}},
		Signals: oadr2b.EventSignals{Signal: []oadr2b.EventSignal{{SignalName: "SIMPLE", SignalType: "level", SignalID: "sig-1",
			Intervals: oadr2b.Intervals{Interval: []oadr2b.Interval{
				{Duration: &oadr2b.DurationProp{Duration: "PT30M"}, UID: &oadr2b.UID{Text: "0"}, SignalPayload: &oadr2b.SignalPayload{PayloadFloat: oadr2b.PayloadFloat{Value: 1}}},
				{Duration: &oadr2b.DurationProp{Duration: "PT30M"}, UID: &oadr2b.UID{Text: "1"}, SignalPayload: &oadr2b.SignalPayload{PayloadFloat: oadr2b.PayloadFloat{Value: 2}}},
			}}}}},
		Target: oadr2b.Target{VenID: []string{"ven-1"}},
	}}
	meta := oadr2b.Report{Duration: &oadr2b.DurationProp{Duration: "PT1H"}, ReportRequestID: "0", ReportSpecifierID: "usage-1",
		ReportName: "METADATA_TELEMETRY_USAGE", CreatedDateTime: ts,
		Descriptions: []oadr2b.ReportDescription{
			{RID: "energy", ReportDataSource: src, ReportType: "usage", ReadingType: "Direct Read", SamplingRate: rate,
				ItemBase: &oadr2b.ItemBase{XMLName: xml.Name{Space: oadr2b.NSPower, Local: "energyReal"}, ItemDescription: "RealEnergy", ItemUnits: "Wh", SiScaleCode: "k"}},
			{RID: "status", ReportDataSource: src, ReportType: "x-resourceStatus", ReadingType: "x-notApplicable", SamplingRate: rate},
		}}
	request := oadr2b.ReportRequest{ReportRequestID: "rr-1", ReportSpecifier: oadr2b.ReportSpecifier{ReportSpecifierID: "usage-1",
		Granularity: oadr2b.DurationProp{Duration: "PT10S"}, ReportBackDuration: oadr2b.DurationProp{Duration: "PT10S"},
		ReportInterval:    &oadr2b.ReportInterval{Properties: oadr2b.Properties{DtStart: oadr2b.DtStart{DateTime: ts}, Duration: oadr2b.DurationProp{Duration: "PT1H"}}},
		SpecifierPayloads: []oadr2b.SpecifierPayload{{RID: "energy", ReadingType: "Direct Read"}}}}
	data := oadr2b.Report{DtStart: start, Duration: min1, ReportRequestID: "rr-1", ReportSpecifierID: "usage-1", ReportName: "TELEMETRY_USAGE", CreatedDateTime: ts,
		Intervals: &oadr2b.Intervals{Interval: []oadr2b.Interval{{DtStart: start, Duration: min1, ReportPayload: []oadr2b.ReportPayload{
			{RID: "energy", PayloadFloat: &oadr2b.PayloadFloat{Value: 1.5}, DataQuality: "Quality Good - Non Specific"}}}}}}
	return map[string]oadr2b.SignedObject{
		"oadrQueryRegistration": {QueryRegistration: &oadr2b.QueryRegistration{RequestID: "req-1"}},
		"oadrCreatePartyRegistration": {CreatePartyRegistration: &oadr2b.CreatePartyRegistration{RequestID: "req-1", VenID: "ven-1",
			ProfileName: oadr2b.ProfileName, TransportName: oadr2b.TransportName, VenName: "sigma-ven", XMLSignature: true, HTTPPullModel: &pull}},
		"oadrCreatedPartyRegistration": {CreatedPartyRegistration: &oadr2b.CreatedPartyRegistration{EiResponse: ok, RegistrationID: "reg-1",
			VenID: "ven-1", VtnID: "VTN-1", Profiles: profiles, PollFreq: &oadr2b.DurationProp{Duration: "PT10S"}}},
		"oadrCancelPartyRegistration":   {CancelPartyRegistration: &oadr2b.CancelPartyRegistration{RequestID: "req-1", RegistrationID: "reg-1", VenID: "ven-1"}},
		"oadrCanceledPartyRegistration": {CanceledPartyRegistration: &oadr2b.CanceledPartyRegistration{EiResponse: ok, RegistrationID: "reg-1", VenID: "ven-1"}},
		"oadrRequestReregistration":     {RequestReregistration: &oadr2b.RequestReregistration{VenID: "ven-1"}},
		"oadrRequestEvent":              {RequestEvent: &oadr2b.RequestEvent{EiRequestEvent: oadr2b.EiRequestEvent{RequestID: "req-1", VenID: "ven-1"}}},
		"oadrDistributeEvent":           {DistributeEvent: &oadr2b.DistributeEvent{EiResponse: &ok, RequestID: "req-2", VtnID: "VTN-1", Events: []oadr2b.OadrEvent{event}}},
		"oadrCreatedEvent": {CreatedEvent: &oadr2b.CreatedEvent{EiCreatedEvent: oadr2b.EiCreatedEvent{EiResponse: oadr2b.EiResponse{ResponseCode: oadr2b.CodeOK},
			EventResponses: &oadr2b.EventResponses{Response: []oadr2b.EventResponse{{ResponseCode: oadr2b.CodeOK, RequestID: "req-2", OptType: "optIn",
				QualifiedEventID: oadr2b.QualifiedEventID{EventID: "ev-1", ModificationNumber: 2}}}}, VenID: "ven-1"}}},
		"oadrRegisterReport":   {RegisterReport: &oadr2b.RegisterReport{RequestID: "req-1", Reports: []oadr2b.Report{meta}, VenID: "ven-1"}},
		"oadrRegisteredReport": {RegisteredReport: &oadr2b.RegisteredReport{EiResponse: ok, ReportRequests: []oadr2b.ReportRequest{request}, VenID: "ven-1"}},
		"oadrCreateReport":     {CreateReport: &oadr2b.CreateReport{RequestID: "req-1", ReportRequests: []oadr2b.ReportRequest{request}, VenID: "ven-1"}},
		"oadrCreatedReport": {CreatedReport: &oadr2b.CreatedReport{EiResponse: ok, PendingReports: oadr2b.PendingReports{ReportRequestID: []string{"rr-1"}},
			VenID: "ven-1"}},
		"oadrUpdateReport":  {UpdateReport: &oadr2b.UpdateReport{RequestID: "req-1", Reports: []oadr2b.Report{data}, VenID: "ven-1"}},
		"oadrUpdatedReport": {UpdatedReport: &oadr2b.UpdatedReport{EiResponse: ok, VenID: "ven-1"}},
		"oadrCancelReport":  {CancelReport: &oadr2b.CancelReport{RequestID: "req-1", ReportRequestID: []string{"rr-1"}, ReportToFollow: false, VenID: "ven-1"}},
		"oadrCanceledReport": {CanceledReport: &oadr2b.CanceledReport{EiResponse: ok, PendingReports: oadr2b.PendingReports{ReportRequestID: []string{"rr-1"}},
			VenID: "ven-1"}},
		"oadrCreateOpt": {CreateOpt: &oadr2b.CreateOpt{OptID: "opt-1", OptType: "optOut", OptReason: "participating", VenID: "ven-1", CreatedDateTime: ts,
			RequestID: "req-1", QualifiedEventID: &oadr2b.QualifiedEventID{EventID: "ev-1", ModificationNumber: 2}, Target: oadr2b.Target{VenID: []string{"ven-1"}}}},
		"oadrCreatedOpt":  {CreatedOpt: &oadr2b.CreatedOpt{EiResponse: ok, OptID: "opt-1"}},
		"oadrCancelOpt":   {CancelOpt: &oadr2b.CancelOpt{RequestID: "req-1", OptID: "opt-1", VenID: "ven-1"}},
		"oadrCanceledOpt": {CanceledOpt: &oadr2b.CanceledOpt{EiResponse: ok, OptID: "opt-1"}},
		"oadrPoll":        {Poll: &oadr2b.Poll{VenID: "ven-1"}},
		"oadrResponse":    {Response: &oadr2b.Response{EiResponse: ok, VenID: "ven-1"}},
	}
}

// OpenLEADR reads every message type this library writes: its 2.0b
// schema check passes, its parser names the message, and the XML
// signatures this library makes (ECDSA and RSA) pass OpenLEADR's
// signature and ReplayProtect checks.
func TestOpenLEADRReadsOurMessages(t *testing.T) {
	needDocker(t)
	build(t, imageOpenLEADR, "openleadr")
	dir := t.TempDir()
	p := startPeer(t, "-v", dir+":/work:ro", "-w", "/peer", imageOpenLEADR, "python", "-u", "check.py")
	p.expect(30*time.Second, "ready")

	ec, _, _ := selfSigned(t, ecKey(t))
	rs, _, _ := selfSigned(t, rsaKey(t))
	signers := map[string]tls.Certificate{"ecdsa": ec, "rsa": rs}
	msgs := ourMessages()
	names := make([]string, 0, len(msgs))
	for n := range msgs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		b, err := oadr2b.Marshal(msgs[name])
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		file := name + ".xml"
		if err := os.WriteFile(filepath.Join(dir, file), b, 0o644); err != nil {
			t.Fatal(err)
		}
		p.send("check /work/" + file)
		if got := p.expect(10*time.Second, "/work/"+file+" "); !strings.HasPrefix(got, "ok ") || !strings.HasSuffix(got, " "+name) {
			t.Errorf("OpenLEADR on our %s: %s", name, got)
		}
		for kind, c := range signers {
			s, err := oadr2b.NewSigner(c)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := s.Sign(b)
			if err != nil {
				t.Fatalf("%s: sign: %v", name, err)
			}
			file := name + "." + kind + ".xml"
			if err := os.WriteFile(filepath.Join(dir, file), signed, 0o644); err != nil {
				t.Fatal(err)
			}
			p.send("check /work/" + file + " " + s.Fingerprint())
			if got := p.expect(10*time.Second, "/work/"+file+" "); !strings.HasPrefix(got, "ok ") {
				t.Errorf("OpenLEADR on our %s signed with %s: %s", name, kind, got)
			}
		}
	}
}

// This library reads every message OpenLEADR writes: Unmarshal gives
// the same message type, VerifyPayload accepts OpenLEADR's signatures
// (signxml) with the signer's certificate and fresh ReplayProtect, the
// schema check of LoadSchemas accepts them with the 2.0b XSDs OpenLEADR
// ships (copied out at test time, not kept), and what Marshal writes
// back from them passes OpenLEADR's own checks.
func TestWeReadOpenLEADRMessages(t *testing.T) {
	needDocker(t)
	build(t, imageOpenLEADR, "openleadr")
	dir := t.TempDir()
	cert, certPEM, keyPEM := selfSigned(t, ecKey(t))
	if err := os.WriteFile(filepath.Join(dir, "olr.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "olr.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	maker := startPeer(t, "-v", dir+":/work", imageOpenLEADR, "python", "-u", "make.py", "/work", "/work/olr.crt", "/work/olr.key")
	maker.expect(60*time.Second, "done")
	if strings.Contains(maker.output(), "PEER fail") {
		t.Fatalf("OpenLEADR could not make every message:\n%s", maker.output())
	}
	schemas, err := oadr2b.LoadSchemas(filepath.Join(dir, "schema"))
	if err != nil {
		t.Fatalf("loading OpenLEADR's copy of the 2.0b schema: %v", err)
	}
	fp := oadr2b.Fingerprint(cert.Certificate[0])
	var guard oadr2b.ReplayGuard
	checker := startPeer(t, "-v", dir+":/work", imageOpenLEADR, "python", "-u", "check.py")
	checker.expect(30*time.Second, "ready")

	names := make([]string, 0)
	for n := range ourMessages() {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name+".xml"))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		so, err := oadr2b.Unmarshal(b)
		if err != nil {
			t.Errorf("Unmarshal of OpenLEADR's %s: %v", name, err)
			continue
		}
		if got := oadr2b.MessageName(so); got != name {
			t.Errorf("OpenLEADR's %s read as %s", name, got)
		}
		v, err := oadr2b.VerifyPayload(b)
		if err != nil {
			t.Errorf("VerifyPayload of OpenLEADR's %s: %v", name, err)
		} else if got := oadr2b.Fingerprint(v.Cert.Raw); got != fp {
			t.Errorf("%s signed by %s, want %s", name, got, fp)
		} else if err := guard.Check(v); err != nil {
			t.Errorf("ReplayGuard on OpenLEADR's %s: %v", name, err)
		}
		if err := schemas.Check(b); err != nil {
			t.Errorf("our schema check of OpenLEADR's %s: %v", name, err)
		}
		checker.send("check /work/" + name + ".xml")
		if got := checker.expect(10*time.Second, "/work/"+name+".xml "); !strings.HasPrefix(got, "ok ") {
			t.Errorf("OpenLEADR's check of its own %s: %s", name, got)
		}
		// Written back by this library, the message still passes
		// OpenLEADR's checks.
		again, err := oadr2b.Marshal(*so)
		if err != nil {
			t.Errorf("Marshal of OpenLEADR's %s: %v", name, err)
			continue
		}
		file := name + ".again.xml"
		if err := os.WriteFile(filepath.Join(dir, file), again, 0o644); err != nil {
			t.Fatal(err)
		}
		checker.send("check /work/" + file)
		if got := checker.expect(10*time.Second, "/work/"+file+" "); !strings.HasPrefix(got, "ok ") {
			t.Errorf("OpenLEADR on its %s written back by us: %s", name, got)
		}
		if err := schemas.Check(again); err != nil {
			t.Errorf("our schema check of %s written back: %v", name, err)
		}
	}
	// Our own messages pass our schema check with OpenLEADR's XSDs too.
	for name, so := range ourMessages() {
		b, err := oadr2b.Marshal(so)
		if err != nil {
			t.Fatal(err)
		}
		if err := schemas.Check(b); err != nil {
			t.Errorf("our schema check of our %s: %v", name, err)
		}
	}
}
