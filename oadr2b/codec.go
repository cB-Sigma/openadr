package oadr2b

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// ItemBase is a member of the emix:itemBase substitution group of a report
// description, specifier payload or event signal: power:energyReal,
// power:powerReal, power:voltage, oadr:current, oadr:pulseCount,
// oadr:customUnit and the like. The common children (description, units,
// SI scale) are kept, with the power items' powerAttributes and the pulse
// count's pulseFactor; the element name says the kind.
type ItemBase struct {
	XMLName         xml.Name
	ItemDescription string
	ItemUnits       string
	SiScaleCode     string
	// PowerAttributes is required by the schema on power:power* items.
	PowerAttributes *PowerAttributes
	// PulseFactor is oadr:pulseFactor of oadr:pulseCount (which has no
	// SI scale code).
	PulseFactor *float64
}

// PowerAttributes is power:powerAttributes.
type PowerAttributes struct {
	Hertz   float64
	Voltage float64
	AC      bool
}

// ItemNamespace is the namespace of a known itemBase element.
func ItemNamespace(local string) string {
	switch local {
	case "current", "frequency", "pulseCount", "customUnit", "currency", "currencyPerKWh", "currencyPerKW",
		"currencyPerThm", "temperature", "Therm":
		return NSOadr
	}
	return NSPower
}

// UnmarshalXML reads the children by local name: their namespace depends
// on the item's (power, oadr or emix).
func (b *ItemBase) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	b.XMLName = start.Name
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "itemDescription":
				err = d.DecodeElement(&b.ItemDescription, &t)
			case "itemUnits":
				err = d.DecodeElement(&b.ItemUnits, &t)
			case "siScaleCode":
				err = d.DecodeElement(&b.SiScaleCode, &t)
			case "pulseFactor":
				var f float64
				if err = d.DecodeElement(&f, &t); err == nil {
					b.PulseFactor = &f
				}
			case "powerAttributes":
				var pa struct {
					Hertz   float64 `xml:"hertz"`
					Voltage float64 `xml:"voltage"`
					AC      bool    `xml:"ac"`
				}
				if err = d.DecodeElement(&pa, &t); err == nil {
					b.PowerAttributes = &PowerAttributes{Hertz: pa.Hertz, Voltage: pa.Voltage, AC: pa.AC}
				}
			default:
				err = d.Skip()
			}
			if err != nil {
				return err
			}
		case xml.EndElement:
			return nil
		}
	}
}

// MarshalXML writes the item with its children in the item's namespace
// (power for power items), the scale code in the siscale namespace, and
// powerAttributes (power:power* items) or pulseFactor (oadr:pulseCount).
func (b ItemBase) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	if b.XMLName.Local == "" {
		return errors.New("an itemBase needs an element name such as power:energyReal")
	}
	ns := b.XMLName.Space
	if ns == "" {
		ns = ItemNamespace(b.XMLName.Local)
	}
	start := xml.StartElement{Name: xml.Name{Space: ns, Local: b.XMLName.Local}}
	if err := e.EncodeToken(start); err != nil {
		return err
	}
	el := func(space, local string, v any) error {
		return e.EncodeElement(v, xml.StartElement{Name: xml.Name{Space: space, Local: local}})
	}
	if err := el(ns, "itemDescription", b.ItemDescription); err != nil {
		return err
	}
	if err := el(ns, "itemUnits", b.ItemUnits); err != nil {
		return err
	}
	if b.XMLName.Local == "pulseCount" {
		f := 1.0
		if b.PulseFactor != nil {
			f = *b.PulseFactor
		}
		if err := el(ns, "pulseFactor", f); err != nil {
			return err
		}
		return e.EncodeToken(start.End())
	}
	scale := b.SiScaleCode
	if scale == "" {
		scale = "none"
	}
	if err := el(NSScale, "siScaleCode", scale); err != nil {
		return err
	}
	if ns == NSPower && strings.HasPrefix(b.XMLName.Local, "power") {
		pa := PowerAttributes{Hertz: 50, Voltage: 230, AC: true}
		if b.PowerAttributes != nil {
			pa = *b.PowerAttributes
		}
		pas := xml.StartElement{Name: xml.Name{Space: NSPower, Local: "powerAttributes"}}
		if err := e.EncodeToken(pas); err != nil {
			return err
		}
		for _, c := range []struct {
			local string
			v     any
		}{{"hertz", pa.Hertz}, {"voltage", pa.Voltage}, {"ac", pa.AC}} {
			if err := el(NSPower, c.local, c.v); err != nil {
				return err
			}
		}
		if err := e.EncodeToken(pas.End()); err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

// Unit is the item's unit with its SI prefix ("kWh" for Wh scaled k);
// "none" and "na" scales add nothing.
func (b *ItemBase) Unit() string {
	if b == nil {
		return ""
	}
	switch b.SiScaleCode {
	case "", "none", "na":
		return b.ItemUnits
	}
	return b.SiScaleCode + b.ItemUnits
}

// ---- documents --------------------------------------------------------------

// Marshal writes one message as an oadrPayload document, with the
// conventional namespace prefixes declared on the root and ei:schemaVersion
// set on the message.
func Marshal(so SignedObject) ([]byte, error) {
	if n := countMessages(&so); n != 1 {
		return nil, fmt.Errorf("an oadrSignedObject holds exactly one message, not %d", n)
	}
	setSchemaVersion(&so)
	// The 2.0b schema qualifies local attributes, so the Id is written
	// as oadr:Id whichever form it was read in (Unmarshal takes both).
	id := so.ID
	so.ID = ""
	raw, err := xml.Marshal(Payload{SignedObject: so})
	if err != nil {
		return nil, err
	}
	out, err := prefixed(raw, prefixes)
	if err != nil || id == "" {
		return out, err
	}
	var attr bytes.Buffer
	attr.WriteString(`<oadr:oadrSignedObject oadr:Id="`)
	_ = xml.EscapeText(&attr, []byte(id))
	attr.WriteString(`">`)
	return bytes.Replace(out, []byte("<oadr:oadrSignedObject>"), attr.Bytes(), 1), nil
}

// Unmarshal reads an oadrPayload document and returns its message.
func Unmarshal(b []byte) (*SignedObject, error) {
	var p Payload
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = true
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("not an OpenADR 2.0b payload: %w", err)
	}
	if n := countMessages(&p.SignedObject); n != 1 {
		return nil, fmt.Errorf("the oadrSignedObject holds %d known messages, want exactly one", n)
	}
	return &p.SignedObject, nil
}

// MessageName is the element name of the message ("oadrPoll"), or "".
func MessageName(so *SignedObject) string {
	v := reflect.ValueOf(so).Elem()
	t := v.Type()
	for i := range t.NumField() {
		f := v.Field(i)
		if f.Kind() == reflect.Pointer && !f.IsNil() {
			tag := t.Field(i).Tag.Get("xml")
			if j := strings.LastIndexByte(tag, ' '); j >= 0 {
				tag = tag[j+1:]
			}
			return tag
		}
	}
	return ""
}

func countMessages(so *SignedObject) int {
	v := reflect.ValueOf(so).Elem()
	n := 0
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.Pointer && !f.IsNil() {
			n++
		}
	}
	return n
}

// setSchemaVersion fills in the message's schemaVersion on a copy of the
// message: so is Marshal's own copy of the SignedObject, but the message it
// points to may be shared (queued messages are marshalled by several
// goroutines), so it is never written in place.
func setSchemaVersion(so *SignedObject) {
	v := reflect.ValueOf(so).Elem()
	for i := range v.NumField() {
		f := v.Field(i)
		if f.Kind() != reflect.Pointer || f.IsNil() {
			continue
		}
		if sv := f.Elem().FieldByName("SchemaVersion"); sv.IsValid() && sv.String() == "" {
			c := reflect.New(f.Elem().Type())
			c.Elem().Set(f.Elem())
			c.Elem().FieldByName("SchemaVersion").SetString(SchemaVersion)
			f.Set(c)
		}
	}
}

// prefixed rewrites encoding/xml's output (a default-namespace declaration
// on every element) into the prefixed form OpenADR implementations expect.
func prefixed(raw []byte, prefixes []struct{ prefix, ns string }) ([]byte, error) {
	byNS := map[string]string{}
	for _, p := range prefixes {
		byNS[p.ns] = p.prefix
	}
	qname := func(n xml.Name) (string, error) {
		if n.Space == "" {
			return n.Local, nil
		}
		p, ok := byNS[n.Space]
		if !ok {
			return "", fmt.Errorf("no prefix for namespace %s", n.Space)
		}
		return p + ":" + n.Local, nil
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	root := true
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name, err := qname(t.Name)
			if err != nil {
				return nil, err
			}
			buf.WriteString("<" + name)
			if root {
				for _, p := range prefixes {
					buf.WriteString(` xmlns:` + p.prefix + `="` + p.ns + `"`)
				}
				root = false
			}
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns") {
					continue
				}
				an, err := qname(a.Name)
				if err != nil {
					return nil, err
				}
				buf.WriteString(" " + an + `="`)
				_ = xml.EscapeText(&buf, []byte(a.Value))
				buf.WriteString(`"`)
			}
			buf.WriteString(">")
		case xml.EndElement:
			name, err := qname(t.Name)
			if err != nil {
				return nil, err
			}
			buf.WriteString("</" + name + ">")
		case xml.CharData:
			_ = xml.EscapeText(&buf, t)
		}
	}
	return buf.Bytes(), nil
}

// ---- values -----------------------------------------------------------------

// FormatTime writes an xcal date-time in UTC.
func FormatTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// ParseTime reads an xcal date-time (RFC 3339, fractional seconds
// allowed). A time without a zone is read as UTC, as rule 1 makes every
// OpenADR time UTC.
func ParseTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		if t2, err2 := time.ParseInLocation("2006-01-02T15:04:05.999999999", s, time.UTC); err2 == nil {
			return t2, nil
		}
	}
	return t, err
}

// FormatDuration writes an ISO 8601 duration ("PT1H30M", "PT0S").
func FormatDuration(d time.Duration) string {
	// Conformance rule 1: no decimal values, so whole seconds only.
	if d = d.Truncate(time.Second); d == 0 {
		return "PT0S"
	}
	var b strings.Builder
	if d < 0 {
		b.WriteByte('-')
		d = -d
	}
	b.WriteString("P")
	if days := d / (24 * time.Hour); days > 0 {
		b.WriteString(strconv.FormatInt(int64(days), 10) + "D")
		d -= days * 24 * time.Hour
	}
	if d == 0 {
		return b.String()
	}
	b.WriteString("T")
	h, m, s := d/time.Hour, (d%time.Hour)/time.Minute, d%time.Minute
	if h > 0 {
		b.WriteString(strconv.FormatInt(int64(h), 10) + "H")
	}
	if m > 0 {
		b.WriteString(strconv.FormatInt(int64(m), 10) + "M")
	}
	if s > 0 {
		b.WriteString(strconv.FormatInt(int64(s/time.Second), 10) + "S")
	}
	return b.String()
}

// ParseDuration reads an ISO 8601 duration of weeks, days, hours, minutes
// and seconds ("PT1H", "P1DT12H", "-PT5M", "PT0.5S"). Years and months have
// no fixed length and are refused.
func ParseDuration(s string) (time.Duration, error) {
	in := strings.TrimSpace(s)
	neg := false
	switch {
	case strings.HasPrefix(in, "-"):
		neg, in = true, in[1:]
	case strings.HasPrefix(in, "+"):
		in = in[1:]
	}
	if len(in) < 2 || in[0] != 'P' {
		return 0, fmt.Errorf("%q is not an ISO 8601 duration such as PT1H", s)
	}
	in = in[1:]
	var total time.Duration
	timePart := false
	num := ""
	seen := false
	for i := 0; i < len(in); i++ {
		c := in[i]
		switch {
		case c == 'T':
			if timePart || num != "" {
				return 0, fmt.Errorf("%q is not an ISO 8601 duration", s)
			}
			timePart = true
		case c >= '0' && c <= '9' || c == '.' || c == ',':
			if c == ',' {
				c = '.'
			}
			num += string(c)
		default:
			if num == "" {
				return 0, fmt.Errorf("%q is not an ISO 8601 duration", s)
			}
			f, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, fmt.Errorf("%q is not an ISO 8601 duration", s)
			}
			var unit time.Duration
			switch {
			case !timePart && c == 'W':
				unit = 7 * 24 * time.Hour
			case !timePart && c == 'D':
				unit = 24 * time.Hour
			case timePart && c == 'H':
				unit = time.Hour
			case timePart && c == 'M':
				unit = time.Minute
			case timePart && c == 'S':
				unit = time.Second
			default:
				return 0, fmt.Errorf("%q: years and months (or unit %c) are not supported in a duration", s, c)
			}
			total += time.Duration(f * float64(unit))
			num, seen = "", true
		}
	}
	if num != "" || !seen {
		return 0, fmt.Errorf("%q is not an ISO 8601 duration", s)
	}
	if neg {
		total = -total
	}
	return total, nil
}

// ---- identity ---------------------------------------------------------------

// Fingerprint is a certificate's OpenADR fingerprint: the last ten bytes of
// the SHA-256 digest of its DER encoding, as colon-separated upper-case hex
// ("AB:CD:…", 29 characters).
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return formatFP(sum[len(sum)-10:])
}

func formatFP(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var out strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(h[i : i+2])
	}
	return out.String()
}

// NormalizeFingerprint accepts a fingerprint written with or without
// colons, in any case, and either the full digest or its last ten bytes,
// and returns the 29-character form.
func NormalizeFingerprint(s string) (string, error) {
	h := strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s))
	b, err := hex.DecodeString(h)
	if err != nil || len(b) < 10 {
		return "", fmt.Errorf("fingerprint %q is not at least ten hex bytes", s)
	}
	return formatFP(b[len(b)-10:]), nil
}

func XMLName(ns, local string) xml.Name { return xml.Name{Space: ns, Local: local} }
