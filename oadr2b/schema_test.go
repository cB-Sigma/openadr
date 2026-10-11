package oadr2b

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The OpenADR schemas are not in the repository (all rights reserved by
// their publisher). SIGMA_TEST_OPENADR_XSD_DIR names a directory holding
// a/xsd (2.0a, root oadr_20a.xsd) and b/xsd (2.0b, root oadr_20b.xsd).
func schemaDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("SIGMA_TEST_OPENADR_XSD_DIR")
	if dir == "" {
		t.Skip("SIGMA_TEST_OPENADR_XSD_DIR is not set: point it at a folder holding a/xsd/oadr_20a.xsd (from the OpenADR Alliance oadr20a_schema.zip) and b/xsd/oadr_20b.xsd (from Profile_B_Schema_20130701.zip, both unzipped); the schemas are not redistributable")
	}
	return dir
}

// zipDir packs a directory tree into a zip archive in memory.
func zipDir(t *testing.T, dir string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Covers: SIG-IPE-2346
func TestSchemaSetLoading(t *testing.T) {
	dir := schemaDir(t)
	if s, err := LoadSchemas(""); s != nil || err != nil {
		t.Fatalf("empty value: %v, %v", s, err)
	}
	var none *SchemaSet
	if err := none.Check([]byte("<anything/>")); err != nil {
		t.Fatalf("nil set rejects: %v", err)
	}
	// both profiles from a directory
	both, err := LoadSchemas(dir)
	if err != nil || both.a == nil || both.b == nil {
		t.Fatalf("directory: %+v, %v", both, err)
	}
	// 2.0b only, inline zip
	inline := "base64:" + base64.StdEncoding.EncodeToString(zipDir(t, filepath.Join(dir, "b")))
	onlyB, err := LoadSchemas(inline)
	if err != nil || onlyB.a != nil || onlyB.b == nil {
		t.Fatalf("inline 2.0b zip: %+v, %v", onlyB, err)
	}
	// 2.0a only, zip file
	zp := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(zp, zipDir(t, filepath.Join(dir, "a")), 0o600); err != nil {
		t.Fatal(err)
	}
	onlyA, err := LoadSchemas(zp)
	if err != nil || onlyA.a == nil || onlyA.b != nil {
		t.Fatalf("2.0a zip file: %+v, %v", onlyA, err)
	}
	poll, err := Marshal(SignedObject{Poll: &Poll{VenID: "ven-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := onlyB.Check(poll); err != nil {
		t.Fatalf("2.0b poll: %v", err)
	}
	if err := onlyA.Check(poll); err == nil || !strings.Contains(err.Error(), "no 2.0b schema") {
		t.Fatalf("2.0b message with only the 2.0a schema: %v", err)
	}
	a := []byte(`<oadr:oadrDistributeEvent xmlns:oadr="` + NSOadr20a + `"/>`)
	if err := onlyB.Check(a); err == nil || !strings.Contains(err.Error(), "no 2.0a schema") {
		t.Fatalf("2.0a message with only the 2.0b schema: %v", err)
	}
	if err := both.Check(a); err == nil || !strings.Contains(err.Error(), "2.0a") {
		t.Fatalf("incomplete 2.0a message accepted: %v", err)
	}
	if err := both.Check([]byte(`<x xmlns="urn:other"/>`)); err == nil {
		t.Fatal("foreign root accepted")
	}
	if _, err := LoadSchemas("base64:!!"); err == nil {
		t.Fatal("bad base64 accepted")
	}
	if _, err := LoadSchemas(t.TempDir()); err == nil {
		t.Fatal("directory without schemas accepted")
	}
}

func f64(v float64) *float64 { return &v }
func u32(v uint32) *uint32   { return &v }
func yes() *bool             { b := true; return &b }

// allMessages builds one realistic instance of every message SignedObject
// carries.
func allMessages() map[string]SignedObject {
	now := "2026-09-25T10:00:00Z"
	resp := EiResponse{ResponseCode: "200", ResponseDescription: "OK", RequestID: "req-1"}
	target := Target{VenID: []string{"ven-1"}, ResourceID: []string{"res-1"}}
	props := Properties{DtStart: DtStart{DateTime: now}, Duration: DurationProp{Duration: "PT1H"},
		Notification: &DurationProp{Duration: "PT10M"}}
	item := &ItemBase{XMLName: XMLName(NSPower, "energyReal"), ItemDescription: "RealEnergy", ItemUnits: "Wh", SiScaleCode: "k"}
	report := Report{
		DtStart:  &DtStart{DateTime: now},
		Duration: &DurationProp{Duration: "PT1H"},
		Intervals: &Intervals{Interval: []Interval{{
			DtStart: &DtStart{DateTime: now}, Duration: &DurationProp{Duration: "PT15M"},
			ReportPayload: []ReportPayload{{RID: "rid-1", Confidence: u32(100), Accuracy: f64(0.5),
				PayloadFloat: &PayloadFloat{Value: 12.5}, DataQuality: "Quality Good - Non Specific"}},
		}}},
		EiReportID:        "rep-1",
		ReportRequestID:   "rr-1",
		ReportSpecifierID: "spec-1",
		ReportName:        "TELEMETRY_USAGE",
		CreatedDateTime:   now,
	}
	metadata := Report{
		Duration:   &DurationProp{Duration: "PT1H"},
		EiReportID: "rep-md",
		Descriptions: []ReportDescription{{
			RID: "rid-1", ReportDataSource: &Target{ResourceID: []string{"res-1"}}, ReportType: "usage",
			ItemBase: item, ReadingType: "Direct Read", MarketContext: "http://market.example/ctx",
			SamplingRate: &SamplingRate{MinPeriod: "PT1M", MaxPeriod: "PT1H", OnChange: false},
		}},
		ReportRequestID:   "0",
		ReportSpecifierID: "METADATA_TELEMETRY_USAGE",
		ReportName:        "METADATA_TELEMETRY_USAGE",
		CreatedDateTime:   now,
	}
	statusReport := Report{
		EiReportID: "rep-st",
		Intervals: &Intervals{Interval: []Interval{{
			DtStart: &DtStart{DateTime: now},
			ReportPayload: []ReportPayload{{RID: "status", ResourceStatus: &ResourceStatus{Online: true,
				LoadControlState: &LoadControlState{SetPoint: &LoadControlValue{Min: f64(18), Max: f64(26), Current: 21}}}}},
		}}},
		ReportRequestID: "rr-2", ReportSpecifierID: "spec-2", ReportName: "TELEMETRY_STATUS", CreatedDateTime: now,
	}
	request := ReportRequest{ReportRequestID: "rr-1", ReportSpecifier: ReportSpecifier{
		ReportSpecifierID: "spec-1", Granularity: DurationProp{Duration: "PT15M"},
		ReportBackDuration: DurationProp{Duration: "PT1H"},
		ReportInterval:     &ReportInterval{Properties: Properties{DtStart: DtStart{DateTime: now}, Duration: DurationProp{Duration: "PT4H"}}},
		SpecifierPayloads:  []SpecifierPayload{{RID: "rid-1", ItemBase: item, ReadingType: "Direct Read"}},
	}}
	event := OadrEvent{
		EiEvent: EiEvent{
			Descriptor: EventDescriptor{EventID: "ev-1", ModificationNumber: 0, Priority: u32(1),
				MarketContext: MarketContext{MarketContext: "http://market.example/ctx"}, CreatedDateTime: now,
				EventStatus: "far", TestEvent: "false", VtnComment: "peak"},
			ActivePeriod: ActivePeriod{Properties: props, Components: Components{Nil: "true"}},
			Signals: EventSignals{Signal: []EventSignal{{
				Intervals: Intervals{Interval: []Interval{{Duration: &DurationProp{Duration: "PT1H"},
					UID: &UID{Text: "0"}, SignalPayload: &SignalPayload{PayloadFloat: PayloadFloat{Value: 1}}}}},
				SignalName: "SIMPLE", SignalType: "level", SignalID: "sig-1",
				CurrentValue: &CurrentValue{PayloadFloat: PayloadFloat{Value: 0}},
			}}},
			Target: target,
		},
		ResponseRequired: "always",
	}
	return map[string]SignedObject{
		"oadrQueryRegistration": {QueryRegistration: &QueryRegistration{RequestID: "req-1"}},
		"oadrCreatePartyRegistration": {CreatePartyRegistration: &CreatePartyRegistration{RequestID: "req-1", VenID: "ven-1",
			ProfileName: "2.0b", TransportName: "simpleHttp", TransportAddress: "https://ven.example/oadr",
			ReportOnly: false, XMLSignature: true, VenName: "ven one", HTTPPullModel: yes()}},
		"oadrCreatedPartyRegistration": {CreatedPartyRegistration: &CreatedPartyRegistration{EiResponse: resp,
			RegistrationID: "reg-1", VenID: "ven-1", VtnID: "vtn-1",
			Profiles: Profiles{Profile: []Profile{{Name: "2.0b", Transports: Transports{Transport: []Transport{{Name: "simpleHttp"}}}}}},
			PollFreq: &DurationProp{Duration: "PT30S"}}},
		"oadrCancelPartyRegistration":   {CancelPartyRegistration: &CancelPartyRegistration{RequestID: "req-1", RegistrationID: "reg-1", VenID: "ven-1"}},
		"oadrCanceledPartyRegistration": {CanceledPartyRegistration: &CanceledPartyRegistration{EiResponse: resp, RegistrationID: "reg-1", VenID: "ven-1"}},
		"oadrRequestReregistration":     {RequestReregistration: &RequestReregistration{VenID: "ven-1"}},
		"oadrResponse":                  {Response: &Response{EiResponse: resp, VenID: "ven-1"}},
		"oadrPoll":                      {Poll: &Poll{VenID: "ven-1"}},
		"oadrRequestEvent":              {RequestEvent: &RequestEvent{EiRequestEvent: EiRequestEvent{RequestID: "req-1", VenID: "ven-1", ReplyLimit: 5}}},
		"oadrDistributeEvent":           {DistributeEvent: &DistributeEvent{EiResponse: &resp, RequestID: "req-1", VtnID: "vtn-1", Events: []OadrEvent{event}}},
		"oadrCreatedEvent": {CreatedEvent: &CreatedEvent{EiCreatedEvent: EiCreatedEvent{EiResponse: resp,
			EventResponses: &EventResponses{Response: []EventResponse{{ResponseCode: "200", ResponseDescription: "OK", RequestID: "req-1",
				QualifiedEventID: QualifiedEventID{EventID: "ev-1", ModificationNumber: 0}, OptType: "optIn"}}},
			VenID: "ven-1"}}},
		"oadrRegisterReport":   {RegisterReport: &RegisterReport{RequestID: "req-1", Reports: []Report{metadata}, VenID: "ven-1"}},
		"oadrRegisteredReport": {RegisteredReport: &RegisteredReport{EiResponse: resp, ReportRequests: []ReportRequest{request}, VenID: "ven-1"}},
		"oadrCreateReport":     {CreateReport: &CreateReport{RequestID: "req-1", ReportRequests: []ReportRequest{request}, VenID: "ven-1"}},
		"oadrCreatedReport":    {CreatedReport: &CreatedReport{EiResponse: resp, PendingReports: PendingReports{ReportRequestID: []string{"rr-1"}}, VenID: "ven-1"}},
		"oadrUpdateReport":     {UpdateReport: &UpdateReport{RequestID: "req-1", Reports: []Report{report, statusReport}, VenID: "ven-1"}},
		"oadrUpdatedReport": {UpdatedReport: &UpdatedReport{EiResponse: resp,
			CancelReport: &CancelReport{RequestID: "req-2", ReportRequestID: []string{"rr-1"}, ReportToFollow: false, VenID: "ven-1"}, VenID: "ven-1"}},
		"oadrCancelReport":   {CancelReport: &CancelReport{RequestID: "req-1", ReportRequestID: []string{"rr-1"}, ReportToFollow: true, VenID: "ven-1"}},
		"oadrCanceledReport": {CanceledReport: &CanceledReport{EiResponse: resp, PendingReports: PendingReports{ReportRequestID: []string{"rr-2"}}, VenID: "ven-1"}},
		"oadrCreateOpt": {CreateOpt: &CreateOpt{OptID: "opt-1", OptType: "optOut", OptReason: "participating",
			MarketContext: "http://market.example/ctx", VenID: "ven-1",
			Vavailability:   &Vavailability{Components: AvailableComponents{Available: []Available{{Properties: props}}}},
			CreatedDateTime: now, RequestID: "req-1", QualifiedEventID: &QualifiedEventID{EventID: "ev-1"},
			Target: target}},
		"oadrCreatedOpt":  {CreatedOpt: &CreatedOpt{EiResponse: resp, OptID: "opt-1"}},
		"oadrCancelOpt":   {CancelOpt: &CancelOpt{RequestID: "req-1", OptID: "opt-1", VenID: "ven-1"}},
		"oadrCanceledOpt": {CanceledOpt: &CanceledOpt{EiResponse: resp, OptID: "opt-1"}},
	}
}

func schemaSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "schema signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A message with a line break before its XML declaration, as some VENs and
// VTNs write, still validates.
//
// Covers: SIG-IPE-2346
func TestSchemaAcceptsSpaceBeforeDeclaration(t *testing.T) {
	both, err := LoadSchemas(schemaDir(t))
	if err != nil {
		t.Fatal(err)
	}
	poll, err := Marshal(SignedObject{Poll: &Poll{VenID: "ven-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(poll), "<?xml") {
		poll = append([]byte(`<?xml version="1.0" encoding="UTF-8"?>`), poll...)
	}
	if err := both.Check(append([]byte("\n"), poll...)); err != nil {
		t.Fatalf("leading white space: %v", err)
	}
}

// A message nested deeper than the xsd module's limit (256) is refused by Check
// like any message that does not validate; the gate then answers it as
// schemaMode says (406 with enforce).
//
// Covers: SIG-IPE-2397
func TestSchemaRefusesDeepMessage(t *testing.T) {
	both, err := LoadSchemas(schemaDir(t))
	if err != nil {
		t.Fatal(err)
	}
	deep := `<oadr:oadrPayload xmlns:oadr="` + NSOadr20b + `">` + strings.Repeat("<oadr:x>", 300) + strings.Repeat("</oadr:x>", 300) + `</oadr:oadrPayload>`
	if err := both.Check([]byte(deep)); err == nil || !strings.Contains(err.Error(), "openadr 2.0b") || !strings.Contains(err.Error(), "nested deeper than 256") {
		t.Fatalf("deep message: %v", err)
	}
}

// Every message the package writes is valid against the OpenADR 2.0b
// schema, and the schema catches a departure in each.
//
// Covers: SIG-IPE-2347
func TestSchemaEvery20bMessage(t *testing.T) {
	set, err := LoadSchemas(filepath.Join(schemaDir(t), "b"))
	if err != nil {
		t.Fatal(err)
	}
	msgs := allMessages()
	// every message field of SignedObject is exercised
	st := reflect.TypeOf(SignedObject{})
	for i := range st.NumField() {
		if st.Field(i).Type.Kind() != reflect.Pointer {
			continue
		}
		tag := st.Field(i).Tag.Get("xml")
		name := tag[strings.LastIndexByte(tag, ' ')+1:]
		if _, ok := msgs[name]; !ok {
			t.Errorf("message %s has no schema test instance", name)
		}
	}
	for name, so := range msgs {
		t.Run(name, func(t *testing.T) {
			doc, err := Marshal(so)
			if err != nil {
				t.Fatal(err)
			}
			if err := set.Check(doc); err != nil {
				t.Errorf("%v\n%s", err, doc)
			}
		})
	}
	// the validator is not vacuous on these schemas
	doc, err := Marshal(msgs["oadrDistributeEvent"])
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct{ from, to, want string }{
		{"<ei:eventStatus>far</ei:eventStatus>", "<ei:eventStatus>later</ei:eventStatus>", "eventStatus"},
		{"<ei:vtnID>vtn-1</ei:vtnID>", "", "vtnID"},
		{"<ei:signalName>SIMPLE</ei:signalName>", "<ei:signalName>x</ei:signalName>", "signalName"},
		{"<xcal:duration>PT1H</xcal:duration>", "<xcal:duration>1 hour</xcal:duration>", "duration"},
		{"<ei:eventID>ev-1</ei:eventID>", "<ei:eventID>ev-1</ei:eventID><ei:bogus/>", "ei:bogus"},
		{`ei:schemaVersion="2.0b"`, `ei:schemaVersion="2.0b" color="red"`, "color"},
	} {
		if !bytes.Contains(doc, []byte(m.from)) {
			t.Errorf("%q not in the marshalled event", m.from)
			continue
		}
		bad := bytes.Replace(doc, []byte(m.from), []byte(m.to), 1)
		if err := set.Check(bad); err == nil || !strings.Contains(err.Error(), m.want) {
			t.Errorf("%s -> %s: %v", m.from, m.to, err)
		}
	}
}

// A signed payload (ds:Signature before oadrSignedObject) is valid against
// the 2.0b schema, with the signed object's Id written qualified (oadr:Id)
// as the schema declares. Not claimed: it needs the schema copy
// (SIGMA_TEST_OPENADR_XSD_DIR).
func TestSchemaSigned20bPayload(t *testing.T) {
	set, err := LoadSchemas(filepath.Join(schemaDir(t), "b"))
	if err != nil {
		t.Fatal(err)
	}
	signer := schemaSigner(t)
	for _, name := range []string{"oadrPoll", "oadrDistributeEvent", "oadrUpdateReport"} {
		doc, err := Marshal(allMessages()[name])
		if err != nil {
			t.Fatal(err)
		}
		signed, err := signer.Sign(doc)
		if err != nil {
			t.Fatal(err)
		}
		if err := set.Check(signed); err != nil {
			t.Errorf("%s signed: %v", name, err)
		}
		// With the Id qualified the rest of the signed payload, ds:Signature
		// included, is valid: that attribute is the only departure.
		q := bytes.Replace(signed, []byte(` Id="`+SignedObjectID+`"`), []byte(` oadr:Id="`+SignedObjectID+`"`), 1)
		if err := set.Check(q); err != nil {
			t.Errorf("%s signed, Id qualified: %v", name, err)
		}
	}
}
