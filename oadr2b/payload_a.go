package oadr2b

// OpenADR 2.0a payloads (2.0a Profile Specification v1.0 and its schema),
// written from element names and namespaces. The A profile has the EiEvent
// service only: oadrRequestEvent, oadrDistributeEvent, oadrCreatedEvent
// and oadrResponse, each the document's root element in the 2.0a
// namespace (no oadrPayload envelope, no XML signature, no schemaVersion
// attribute). The Energy Interoperation parts inside keep the same
// namespaces as in 2.0b, so the 2.0b types are reused for them.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// NSOadrA is the 2.0a namespace.
const NSOadrA = "http://openadr.org/oadr-2.0a/2012/07"

// Profile names (setting profile and oadrProfileName).
const (
	Profile20a = "2.0a"
	Profile20b = "2.0b"
)

// PathBaseA is the 2.0a simple-HTTP path before the service name (2.0a
// section 9.1.2; 2.0b adds "2.0b/").
const PathBaseA = "/OpenADR2/Simple/"

var prefixesA = []struct{ prefix, ns string }{
	{"oadr", NSOadrA}, {"ei", NSEi}, {"pyld", NSPyld}, {"xcal", NSXcal}, {"strm", NSStrm}, {"emix", NSEmix}, {"xsi", NSXsi},
}

// MessageA is one 2.0a message; exactly one member is set.
type MessageA struct {
	DistributeEvent *DistributeEventA
	CreatedEvent    *CreatedEventA
	RequestEvent    *RequestEventA
	Response        *ResponseA
}

// DistributeEventA is 2.0a oadrDistributeEvent.
type DistributeEventA struct {
	XMLName    xml.Name     `xml:"http://openadr.org/oadr-2.0a/2012/07 oadrDistributeEvent"`
	EiResponse *EiResponse  `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
	RequestID  string       `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads requestID"`
	VtnID      string       `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 vtnID"`
	Events     []OadrEventA `xml:"http://openadr.org/oadr-2.0a/2012/07 oadrEvent"`
}

// OadrEventA is one 2.0a event.
type OadrEventA struct {
	EiEvent          EiEvent `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiEvent"`
	ResponseRequired string  `xml:"http://openadr.org/oadr-2.0a/2012/07 oadrResponseRequired"`
}

// CreatedEventA is 2.0a oadrCreatedEvent.
type CreatedEventA struct {
	XMLName        xml.Name       `xml:"http://openadr.org/oadr-2.0a/2012/07 oadrCreatedEvent"`
	EiCreatedEvent EiCreatedEvent `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads eiCreatedEvent"`
}

// RequestEventA is 2.0a oadrRequestEvent.
type RequestEventA struct {
	XMLName        xml.Name       `xml:"http://openadr.org/oadr-2.0a/2012/07 oadrRequestEvent"`
	EiRequestEvent EiRequestEvent `xml:"http://docs.oasis-open.org/ns/energyinterop/201110/payloads eiRequestEvent"`
}

// ResponseA is 2.0a oadrResponse (no venID in A).
type ResponseA struct {
	XMLName    xml.Name   `xml:"http://openadr.org/oadr-2.0a/2012/07 oadrResponse"`
	EiResponse EiResponse `xml:"http://docs.oasis-open.org/ns/energyinterop/201110 eiResponse"`
}

// MarshalA writes one 2.0a message with the conventional prefixes.
func MarshalA(m MessageA) ([]byte, error) {
	var v any
	n := 0
	for _, x := range []any{m.DistributeEvent, m.CreatedEvent, m.RequestEvent, m.Response} {
		switch p := x.(type) {
		case *DistributeEventA:
			if p != nil {
				v, n = p, n+1
			}
		case *CreatedEventA:
			if p != nil {
				v, n = p, n+1
			}
		case *RequestEventA:
			if p != nil {
				v, n = p, n+1
			}
		case *ResponseA:
			if p != nil {
				v, n = p, n+1
			}
		}
	}
	if n != 1 {
		return nil, fmt.Errorf("a 2.0a document holds exactly one message, not %d", n)
	}
	raw, err := xml.Marshal(v)
	if err != nil {
		return nil, err
	}
	return prefixed(raw, prefixesA)
}

// UnmarshalA reads a 2.0a document.
func UnmarshalA(b []byte) (*MessageA, error) {
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	var start xml.StartElement
	for {
		tok, err := d.Token()
		if err != nil {
			return nil, fmt.Errorf("not an OpenADR 2.0a payload: %w", err)
		}
		if s, ok := tok.(xml.StartElement); ok {
			start = s
			break
		}
	}
	if start.Name.Space != NSOadrA {
		return nil, fmt.Errorf("the root element is in namespace %q, not the 2.0a namespace", start.Name.Space)
	}
	m := &MessageA{}
	var err error
	switch start.Name.Local {
	case "oadrDistributeEvent":
		m.DistributeEvent = &DistributeEventA{}
		err = d.DecodeElement(m.DistributeEvent, &start)
	case "oadrCreatedEvent":
		m.CreatedEvent = &CreatedEventA{}
		err = d.DecodeElement(m.CreatedEvent, &start)
	case "oadrRequestEvent":
		m.RequestEvent = &RequestEventA{}
		err = d.DecodeElement(m.RequestEvent, &start)
	case "oadrResponse":
		m.Response = &ResponseA{}
		err = d.DecodeElement(m.Response, &start)
	default:
		return nil, fmt.Errorf("%s is not a 2.0a message", start.Name.Local)
	}
	if err != nil {
		return nil, fmt.Errorf("not an OpenADR 2.0a payload: %w", err)
	}
	return m, nil
}

// NameA is the message's element name.
func (m *MessageA) NameA() string {
	switch {
	case m.DistributeEvent != nil:
		return "oadrDistributeEvent"
	case m.CreatedEvent != nil:
		return "oadrCreatedEvent"
	case m.RequestEvent != nil:
		return "oadrRequestEvent"
	case m.Response != nil:
		return "oadrResponse"
	}
	return ""
}

// ToA maps a 2.0b event down to what the A profile allows (2.0b section
// 7.1): one signal named SIMPLE with levels 0 to 3, no
// modificationDateTime or modificationReason, event targets limited to
// groupID, resourceID, venID and partyID, and currentValue always present.
// Events that cannot be expressed (any other signal) are not sent to an A
// VEN: ok is false.
func ToA(e OadrEvent) (OadrEventA, bool) {
	sigs := e.EiEvent.Signals.Signal
	if len(sigs) != 1 || !strings.EqualFold(sigs[0].SignalName, "SIMPLE") {
		return OadrEventA{}, false
	}
	for _, iv := range sigs[0].Intervals.Interval {
		if iv.SignalPayload == nil {
			return OadrEventA{}, false
		}
		v := iv.SignalPayload.PayloadFloat.Value
		if v != 0 && v != 1 && v != 2 && v != 3 {
			return OadrEventA{}, false
		}
	}
	ev := e.EiEvent
	ev.Descriptor.ModificationDateTime, ev.Descriptor.ModificationReason = "", ""
	ev.Target = Target{GroupID: ev.Target.GroupID, ResourceID: ev.Target.ResourceID, VenID: ev.Target.VenID, PartyID: ev.Target.PartyID}
	sig := sigs[0]
	// No signal-level target or itemBase in A (section 7.1); no baseline.
	sig.Target, sig.ItemBase = nil, nil
	if sig.CurrentValue == nil {
		sig.CurrentValue = &CurrentValue{}
	}
	ivs := make([]Interval, len(sig.Intervals.Interval))
	for i, iv := range sig.Intervals.Interval {
		ivs[i] = Interval{Duration: iv.Duration, UID: iv.UID, SignalPayload: iv.SignalPayload}
		if ivs[i].Duration == nil {
			ivs[i].Duration = &DurationProp{Duration: "PT0S"}
		}
		if ivs[i].UID == nil {
			ivs[i].UID = &UID{Text: fmt.Sprint(i)}
		}
	}
	sig.Intervals = Intervals{Interval: ivs}
	ev.Signals = EventSignals{Signal: []EventSignal{sig}}
	if ev.ActivePeriod.Properties.Notification == nil {
		ev.ActivePeriod.Properties.Notification = &DurationProp{Duration: "PT0S"}
	}
	return OadrEventA{EiEvent: ev, ResponseRequired: e.ResponseRequired}, true
}
