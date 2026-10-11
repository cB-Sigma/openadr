package oadr2b_test

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// doc wraps a message in an oadrPayload with the usual prefixes. The
// example messages below are our own, written for these tests.
func doc(msg string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<oadr:oadrPayload xmlns:oadr="http://openadr.org/oadr-2.0b/2012/07"
  xmlns:ei="http://docs.oasis-open.org/ns/energyinterop/201110"
  xmlns:pyld="http://docs.oasis-open.org/ns/energyinterop/201110/payloads"
  xmlns:xcal="urn:ietf:params:xml:ns:icalendar-2.0"
  xmlns:strm="urn:ietf:params:xml:ns:icalendar-2.0:stream"
  xmlns:emix="http://docs.oasis-open.org/ns/emix/2011/06"
  xmlns:power="http://docs.oasis-open.org/ns/emix/2011/06/power"
  xmlns:scale="http://docs.oasis-open.org/ns/emix/2011/06/siscale"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <oadr:oadrSignedObject>` + msg + `</oadr:oadrSignedObject>
</oadr:oadrPayload>`
}

const resp200 = `<ei:eiResponse><ei:responseCode>200</ei:responseCode><ei:responseDescription>OK</ei:responseDescription><pyld:requestID>rq-9</pyld:requestID></ei:eiResponse>`

var examples = map[string]string{
	"oadrQueryRegistration": `<oadr:oadrQueryRegistration ei:schemaVersion="2.0b"><pyld:requestID>rq-1</pyld:requestID></oadr:oadrQueryRegistration>`,
	"oadrCreatedPartyRegistration": `<oadr:oadrCreatedPartyRegistration ei:schemaVersion="2.0b">` + resp200 +
		`<ei:registrationID>reg-42</ei:registrationID><ei:venID>ven-pune-3</ei:venID><ei:vtnID>sigma-vtn</ei:vtnID>
		<oadr:oadrProfiles><oadr:oadrProfile><oadr:oadrProfileName>2.0b</oadr:oadrProfileName>
		<oadr:oadrTransports><oadr:oadrTransport><oadr:oadrTransportName>simpleHttp</oadr:oadrTransportName></oadr:oadrTransport></oadr:oadrTransports>
		</oadr:oadrProfile></oadr:oadrProfiles>
		<oadr:oadrRequestedOadrPollFreq><xcal:duration>PT15S</xcal:duration></oadr:oadrRequestedOadrPollFreq></oadr:oadrCreatedPartyRegistration>`,
	"oadrCreatePartyRegistration": `<oadr:oadrCreatePartyRegistration ei:schemaVersion="2.0b"><pyld:requestID>rq-2</pyld:requestID>
		<ei:venID>ven-pune-3</ei:venID><oadr:oadrProfileName>2.0b</oadr:oadrProfileName><oadr:oadrTransportName>simpleHttp</oadr:oadrTransportName>
		<oadr:oadrTransportAddress>https://10.1.2.3:9443</oadr:oadrTransportAddress><oadr:oadrReportOnly>false</oadr:oadrReportOnly>
		<oadr:oadrXmlSignature>false</oadr:oadrXmlSignature><oadr:oadrVenName>chiller-plant</oadr:oadrVenName>
		<oadr:oadrHttpPullModel>false</oadr:oadrHttpPullModel></oadr:oadrCreatePartyRegistration>`,
	"oadrCancelPartyRegistration":   `<oadr:oadrCancelPartyRegistration ei:schemaVersion="2.0b"><pyld:requestID>rq-3</pyld:requestID><ei:registrationID>reg-42</ei:registrationID><ei:venID>ven-pune-3</ei:venID></oadr:oadrCancelPartyRegistration>`,
	"oadrCanceledPartyRegistration": `<oadr:oadrCanceledPartyRegistration ei:schemaVersion="2.0b">` + resp200 + `<ei:registrationID>reg-42</ei:registrationID><ei:venID>ven-pune-3</ei:venID></oadr:oadrCanceledPartyRegistration>`,
	"oadrRequestReregistration":     `<oadr:oadrRequestReregistration ei:schemaVersion="2.0b"><ei:venID>ven-pune-3</ei:venID></oadr:oadrRequestReregistration>`,
	"oadrResponse":                  `<oadr:oadrResponse ei:schemaVersion="2.0b">` + resp200 + `<ei:venID>ven-pune-3</ei:venID></oadr:oadrResponse>`,
	"oadrPoll":                      `<oadr:oadrPoll ei:schemaVersion="2.0b"><ei:venID>ven-pune-3</ei:venID></oadr:oadrPoll>`,
	"oadrRequestEvent": `<oadr:oadrRequestEvent ei:schemaVersion="2.0b"><pyld:eiRequestEvent><pyld:requestID>rq-4</pyld:requestID>
		<ei:venID>ven-pune-3</ei:venID><pyld:replyLimit>5</pyld:replyLimit></pyld:eiRequestEvent></oadr:oadrRequestEvent>`,
	"oadrDistributeEvent": `<oadr:oadrDistributeEvent ei:schemaVersion="2.0b">` + resp200 + `<pyld:requestID>rq-5</pyld:requestID><ei:vtnID>sigma-vtn</ei:vtnID>
		<oadr:oadrEvent><ei:eiEvent>
		  <ei:eventDescriptor><ei:eventID>peak-0917</ei:eventID><ei:modificationNumber>2</ei:modificationNumber>
		    <ei:priority>1</ei:priority><ei:eiMarketContext><emix:marketContext>http://grid.example.in/dr/summer</emix:marketContext></ei:eiMarketContext>
		    <ei:createdDateTime>2026-09-17T08:00:00Z</ei:createdDateTime><ei:eventStatus>far</ei:eventStatus><ei:testEvent>false</ei:testEvent></ei:eventDescriptor>
		  <ei:eiActivePeriod><xcal:properties><xcal:dtstart><xcal:date-time>2026-09-17T12:30:00Z</xcal:date-time></xcal:dtstart>
		    <xcal:duration><xcal:duration>PT2H</xcal:duration></xcal:duration>
		    <ei:x-eiNotification><xcal:duration>P1D</xcal:duration></ei:x-eiNotification></xcal:properties>
		    <xcal:components xsi:nil="true"/></ei:eiActivePeriod>
		  <ei:eiEventSignals><ei:eiEventSignal><strm:intervals>
		    <ei:interval><xcal:duration><xcal:duration>PT1H</xcal:duration></xcal:duration><xcal:uid><xcal:text>0</xcal:text></xcal:uid>
		      <ei:signalPayload><ei:payloadFloat><ei:value>1</ei:value></ei:payloadFloat></ei:signalPayload></ei:interval>
		    <ei:interval><xcal:duration><xcal:duration>PT1H</xcal:duration></xcal:duration><xcal:uid><xcal:text>1</xcal:text></xcal:uid>
		      <ei:signalPayload><ei:payloadFloat><ei:value>3</ei:value></ei:payloadFloat></ei:signalPayload></ei:interval>
		    </strm:intervals><ei:signalName>SIMPLE</ei:signalName><ei:signalType>level</ei:signalType><ei:signalID>sig-a</ei:signalID>
		    <ei:currentValue><ei:payloadFloat><ei:value>0</ei:value></ei:payloadFloat></ei:currentValue></ei:eiEventSignal></ei:eiEventSignals>
		  <ei:eiTarget><ei:venID>ven-pune-3</ei:venID><ei:venID>ven-pune-4</ei:venID></ei:eiTarget>
		</ei:eiEvent><oadr:oadrResponseRequired>always</oadr:oadrResponseRequired></oadr:oadrEvent></oadr:oadrDistributeEvent>`,
	"oadrCreatedEvent": `<oadr:oadrCreatedEvent ei:schemaVersion="2.0b"><ei:eiCreatedEvent>` + resp200 + `<ei:eventResponses>
		<ei:eventResponse><ei:responseCode>200</ei:responseCode><pyld:requestID>rq-5</pyld:requestID>
		<ei:qualifiedEventID><ei:eventID>peak-0917</ei:eventID><ei:modificationNumber>2</ei:modificationNumber></ei:qualifiedEventID>
		<ei:optType>optOut</ei:optType></ei:eventResponse></ei:eventResponses><ei:venID>ven-pune-3</ei:venID></ei:eiCreatedEvent></oadr:oadrCreatedEvent>`,
	"oadrRegisterReport": `<oadr:oadrRegisterReport ei:schemaVersion="2.0b"><pyld:requestID>rq-6</pyld:requestID>
		<oadr:oadrReport><xcal:duration><xcal:duration>PT2H</xcal:duration></xcal:duration>
		  <oadr:oadrReportDescription><ei:rID>meter-kwh</ei:rID><ei:reportDataSource><ei:resourceID>main-incomer</ei:resourceID></ei:reportDataSource>
		    <ei:reportType>usage</ei:reportType>
		    <power:energyReal><power:itemDescription>RealEnergy</power:itemDescription><power:itemUnits>Wh</power:itemUnits><scale:siScaleCode>k</scale:siScaleCode></power:energyReal>
		    <ei:readingType>Direct Read</ei:readingType>
		    <oadr:oadrSamplingRate><oadr:oadrMinPeriod>PT5M</oadr:oadrMinPeriod><oadr:oadrMaxPeriod>PT15M</oadr:oadrMaxPeriod><oadr:oadrOnChange>false</oadr:oadrOnChange></oadr:oadrSamplingRate>
		  </oadr:oadrReportDescription>
		  <oadr:oadrReportDescription><ei:rID>flow</ei:rID><ei:reportType>usage</ei:reportType>
		    <oadr:customUnit><oadr:itemDescription>ChilledWaterFlow</oadr:itemDescription><oadr:itemUnits>m3/h</oadr:itemUnits><scale:siScaleCode>none</scale:siScaleCode></oadr:customUnit>
		    <ei:readingType>Direct Read</ei:readingType></oadr:oadrReportDescription>
		  <ei:reportRequestID>0</ei:reportRequestID><ei:reportSpecifierID>spec-usage</ei:reportSpecifierID>
		  <ei:reportName>METADATA_TELEMETRY_USAGE</ei:reportName><ei:createdDateTime>2026-09-17T08:00:00Z</ei:createdDateTime></oadr:oadrReport>
		<ei:venID>ven-pune-3</ei:venID></oadr:oadrRegisterReport>`,
	"oadrRegisteredReport": `<oadr:oadrRegisteredReport ei:schemaVersion="2.0b">` + resp200 + `<oadr:oadrReportRequest><ei:reportRequestID>sub-1</ei:reportRequestID>
		<ei:reportSpecifier><ei:reportSpecifierID>spec-usage</ei:reportSpecifierID><xcal:granularity><xcal:duration>PT5M</xcal:duration></xcal:granularity>
		<ei:reportBackDuration><xcal:duration>PT15M</xcal:duration></ei:reportBackDuration>
		<ei:reportInterval><xcal:properties><xcal:dtstart><xcal:date-time>2026-09-17T08:00:00Z</xcal:date-time></xcal:dtstart><xcal:duration><xcal:duration>P1D</xcal:duration></xcal:duration></xcal:properties></ei:reportInterval>
		<ei:specifierPayload><ei:rID>meter-kwh</ei:rID><ei:readingType>Direct Read</ei:readingType></ei:specifierPayload></ei:reportSpecifier>
		</oadr:oadrReportRequest><ei:venID>ven-pune-3</ei:venID></oadr:oadrRegisteredReport>`,
	"oadrCreateReport": `<oadr:oadrCreateReport ei:schemaVersion="2.0b"><pyld:requestID>rq-7</pyld:requestID><oadr:oadrReportRequest><ei:reportRequestID>sub-2</ei:reportRequestID>
		<ei:reportSpecifier><ei:reportSpecifierID>spec-status</ei:reportSpecifierID><xcal:granularity><xcal:duration>PT1M</xcal:duration></xcal:granularity>
		<ei:reportBackDuration><xcal:duration>PT1M</xcal:duration></ei:reportBackDuration>
		<ei:specifierPayload><ei:rID>online</ei:rID><ei:readingType>x-notApplicable</ei:readingType></ei:specifierPayload></ei:reportSpecifier>
		</oadr:oadrReportRequest><ei:venID>ven-pune-3</ei:venID></oadr:oadrCreateReport>`,
	"oadrCreatedReport": `<oadr:oadrCreatedReport ei:schemaVersion="2.0b">` + resp200 + `<oadr:oadrPendingReports><ei:reportRequestID>sub-1</ei:reportRequestID><ei:reportRequestID>sub-2</ei:reportRequestID></oadr:oadrPendingReports><ei:venID>ven-pune-3</ei:venID></oadr:oadrCreatedReport>`,
	"oadrUpdateReport": `<oadr:oadrUpdateReport ei:schemaVersion="2.0b"><pyld:requestID>rq-8</pyld:requestID>
		<oadr:oadrReport><xcal:dtstart><xcal:date-time>2026-09-17T09:00:00Z</xcal:date-time></xcal:dtstart><xcal:duration><xcal:duration>PT10M</xcal:duration></xcal:duration>
		  <strm:intervals>
		    <ei:interval><xcal:dtstart><xcal:date-time>2026-09-17T09:00:00Z</xcal:date-time></xcal:dtstart><xcal:duration><xcal:duration>PT5M</xcal:duration></xcal:duration><xcal:uid><xcal:text>0</xcal:text></xcal:uid>
		      <oadr:oadrReportPayload><ei:rID>meter-kwh</ei:rID><ei:confidence>100</ei:confidence><ei:accuracy>0.5</ei:accuracy>
		        <ei:payloadFloat><ei:value>1520.25</ei:value></ei:payloadFloat><oadr:oadrDataQuality>Quality Good - Non Specific</oadr:oadrDataQuality></oadr:oadrReportPayload></ei:interval>
		    <ei:interval><xcal:dtstart><xcal:date-time>2026-09-17T09:05:00Z</xcal:date-time></xcal:dtstart><xcal:duration><xcal:duration>PT5M</xcal:duration></xcal:duration>
		      <oadr:oadrReportPayload><ei:rID>online</ei:rID><oadr:oadrPayloadResourceStatus><oadr:oadrOnline>true</oadr:oadrOnline><oadr:oadrManualOverride>true</oadr:oadrManualOverride>
		        <oadr:oadrLoadControlState><oadr:oadrLevelOffset><oadr:oadrCurrent>-2</oadr:oadrCurrent></oadr:oadrLevelOffset></oadr:oadrLoadControlState></oadr:oadrPayloadResourceStatus></oadr:oadrReportPayload></ei:interval>
		  </strm:intervals>
		  <ei:reportRequestID>sub-1</ei:reportRequestID><ei:reportSpecifierID>spec-usage</ei:reportSpecifierID><ei:reportName>TELEMETRY_USAGE</ei:reportName>
		  <ei:createdDateTime>2026-09-17T09:10:02Z</ei:createdDateTime></oadr:oadrReport><ei:venID>ven-pune-3</ei:venID></oadr:oadrUpdateReport>`,
	"oadrUpdatedReport": `<oadr:oadrUpdatedReport ei:schemaVersion="2.0b">` + resp200 + `<ei:venID>ven-pune-3</ei:venID></oadr:oadrUpdatedReport>`,
	"oadrCancelReport": `<oadr:oadrCancelReport ei:schemaVersion="2.0b"><pyld:requestID>rq-10</pyld:requestID><ei:reportRequestID>sub-2</ei:reportRequestID>
		<pyld:reportToFollow>true</pyld:reportToFollow><ei:venID>ven-pune-3</ei:venID></oadr:oadrCancelReport>`,
	"oadrCanceledReport": `<oadr:oadrCanceledReport ei:schemaVersion="2.0b">` + resp200 + `<oadr:oadrPendingReports><ei:reportRequestID>sub-1</ei:reportRequestID></oadr:oadrPendingReports><ei:venID>ven-pune-3</ei:venID></oadr:oadrCanceledReport>`,
	"oadrCreateOpt": `<oadr:oadrCreateOpt ei:schemaVersion="2.0b"><ei:optID>opt-77</ei:optID><ei:optType>optOut</ei:optType><ei:optReason>emergency</ei:optReason>
		<emix:marketContext>http://grid.example.in/dr/summer</emix:marketContext><ei:venID>ven-pune-3</ei:venID>
		<ei:createdDateTime>2026-09-17T10:00:00Z</ei:createdDateTime><pyld:requestID>rq-11</pyld:requestID>
		<ei:qualifiedEventID><ei:eventID>peak-0917</ei:eventID><ei:modificationNumber>2</ei:modificationNumber></ei:qualifiedEventID>
		<ei:eiTarget><ei:resourceID>chiller-2</ei:resourceID></ei:eiTarget></oadr:oadrCreateOpt>`,
	"oadrCreatedOpt":  `<oadr:oadrCreatedOpt ei:schemaVersion="2.0b">` + resp200 + `<ei:optID>opt-77</ei:optID></oadr:oadrCreatedOpt>`,
	"oadrCancelOpt":   `<oadr:oadrCancelOpt ei:schemaVersion="2.0b"><pyld:requestID>rq-12</pyld:requestID><ei:optID>opt-77</ei:optID><ei:venID>ven-pune-3</ei:venID></oadr:oadrCancelOpt>`,
	"oadrCanceledOpt": `<oadr:oadrCanceledOpt ei:schemaVersion="2.0b">` + resp200 + `<ei:optID>opt-77</ei:optID></oadr:oadrCanceledOpt>`,
}

// Covers: SIG-IPE-455
func TestOpenADRPayloadRoundTrip(t *testing.T) {
	if len(examples) != 23 {
		t.Fatalf("%d examples, want one per message type (23)", len(examples))
	}
	for name, msg := range examples {
		so, err := oadr2b.Unmarshal([]byte(doc(msg)))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := oadr2b.MessageName(so); got != name {
			t.Errorf("%s decoded as %s", name, got)
		}
		out, err := oadr2b.Marshal(*so)
		if err != nil {
			t.Errorf("%s: marshal: %v", name, err)
			continue
		}
		s := string(out)
		if !strings.Contains(s, "<oadr:oadrPayload xmlns:oadr=\""+oadr2b.NSOadr+"\"") || !strings.Contains(s, "<oadr:"+name+" ei:schemaVersion=\"2.0b\">") {
			t.Errorf("%s: output lacks the prefixed envelope or schemaVersion:\n%s", name, s)
		}
		if strings.Contains(s, ` xmlns="`) {
			t.Errorf("%s: output uses default-namespace declarations:\n%s", name, s)
		}
		again, err := oadr2b.Unmarshal(out)
		if err != nil {
			t.Errorf("%s: re-reading our output: %v\n%s", name, err, s)
			continue
		}
		if !reflect.DeepEqual(so, again) {
			t.Errorf("%s: round trip differs\nfirst:  %+v\nsecond: %+v", name, so, again)
		}
	}

	// Spot checks of the decoded values.
	so, _ := oadr2b.Unmarshal([]byte(doc(examples["oadrDistributeEvent"])))
	ev := so.DistributeEvent.Events[0].EiEvent
	if ev.Descriptor.EventID != "peak-0917" || ev.Descriptor.ModificationNumber != 2 || *ev.Descriptor.Priority != 1 ||
		ev.Descriptor.MarketContext.MarketContext != "http://grid.example.in/dr/summer" ||
		ev.ActivePeriod.Properties.DtStart.DateTime != "2026-09-17T12:30:00Z" || ev.ActivePeriod.Properties.Duration.Duration != "PT2H" ||
		ev.ActivePeriod.Components.Nil != "true" || len(ev.Signals.Signal[0].Intervals.Interval) != 2 ||
		ev.Signals.Signal[0].Intervals.Interval[1].SignalPayload.PayloadFloat.Value != 3 ||
		!reflect.DeepEqual(ev.Target.VenID, []string{"ven-pune-3", "ven-pune-4"}) {
		t.Errorf("distributeEvent decoded as %+v", ev)
	}
	so, _ = oadr2b.Unmarshal([]byte(doc(examples["oadrRegisterReport"])))
	descs := so.RegisterReport.Reports[0].Descriptions
	if descs[0].ItemBase.Unit() != "kWh" || descs[0].ItemBase.XMLName.Space != oadr2b.NSPower || descs[0].SamplingRate.MinPeriod != "PT5M" ||
		descs[0].ReportDataSource.ResourceID[0] != "main-incomer" || descs[1].ItemBase.Unit() != "m3/h" || descs[1].ItemBase.XMLName.Local != "customUnit" {
		t.Errorf("report descriptions decoded as %+v / %+v", descs[0].ItemBase, descs[1].ItemBase)
	}
	so, _ = oadr2b.Unmarshal([]byte(doc(examples["oadrUpdateReport"])))
	ivs := so.UpdateReport.Reports[0].Intervals.Interval
	if ivs[0].ReportPayload[0].PayloadFloat.Value != 1520.25 || *ivs[0].ReportPayload[0].Confidence != 100 ||
		!ivs[1].ReportPayload[0].ResourceStatus.ManualOverride || ivs[1].ReportPayload[0].ResourceStatus.LoadControlState.LevelOffset.Current != -2 {
		t.Errorf("update report decoded as %+v", ivs)
	}
	so, _ = oadr2b.Unmarshal([]byte(doc(examples["oadrCreatePartyRegistration"])))
	if c := so.CreatePartyRegistration; c.HTTPPullModel == nil || *c.HTTPPullModel || c.TransportAddress != "https://10.1.2.3:9443" || c.VenName != "chiller-plant" {
		t.Errorf("createPartyRegistration decoded as %+v", c)
	}

	// Malformed and ambiguous documents are refused.
	for _, bad := range []string{
		"<notOpenADR/>",
		doc(""),
		doc(examples["oadrPoll"] + examples["oadrQueryRegistration"]),
		strings.Replace(doc(examples["oadrPoll"]), "</oadr:oadrPayload>", "", 1),
	} {
		if _, err := oadr2b.Unmarshal([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := oadr2b.Marshal(oadr2b.SignedObject{}); err == nil {
		t.Error("marshalled an empty signed object")
	}
}

// Covers: SIG-IPE-455
func TestOpenADRDurationsAndFingerprints(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"PT1H": time.Hour, "PT15S": 15 * time.Second, "P1D": 24 * time.Hour, "P1DT2H30M": 26*time.Hour + 30*time.Minute,
		"-PT5M": -5 * time.Minute, "PT0.5S": 500 * time.Millisecond, "P1W": 7 * 24 * time.Hour, "PT0S": 0,
	} {
		got, err := oadr2b.ParseDuration(in)
		if err != nil || got != want {
			t.Errorf("ParseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "P", "PT", "1H", "P1M", "P1Y", "PT1D", "PTH"} {
		if _, err := oadr2b.ParseDuration(bad); err == nil {
			t.Errorf("ParseDuration(%q) accepted", bad)
		}
	}
	for d, want := range map[time.Duration]string{
		time.Hour: "PT1H", 90 * time.Minute: "PT1H30M", 0: "PT0S", 48 * time.Hour: "P2D", 25*time.Hour + time.Second: "P1DT1H1S", -time.Minute: "-PT1M",
	} {
		if got := oadr2b.FormatDuration(d); got != want {
			t.Errorf("FormatDuration(%v) = %s, want %s", d, got, want)
		}
	}
	der := []byte("not really a certificate, but any DER bytes will do")
	sum := sha256.Sum256(der)
	full := strings.ToUpper(hex.EncodeToString(sum[:]))
	fp := oadr2b.Fingerprint(der)
	if len(fp) != 29 || strings.ReplaceAll(fp, ":", "") != full[len(full)-20:] {
		t.Errorf("fingerprint %s is not the last ten bytes of %s", fp, full)
	}
	// The full colon-separated digest (as openssl prints it) and lower
	// case forms normalise to the same fingerprint.
	var colon []string
	for i := 0; i < len(full); i += 2 {
		colon = append(colon, full[i:i+2])
	}
	for _, in := range []string{fp, strings.ToLower(fp), strings.Join(colon, ":"), full} {
		if got, err := oadr2b.NormalizeFingerprint(in); err != nil || got != fp {
			t.Errorf("NormalizeFingerprint(%q) = %s, %v", in, got, err)
		}
	}
	if _, err := oadr2b.NormalizeFingerprint("AB:CD"); err == nil {
		t.Error("a two-byte fingerprint was accepted")
	}
}
