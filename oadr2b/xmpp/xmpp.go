// Package xmpp is the small part of XMPP (RFC 6120, RFC 6121, XEP-0030,
// XEP-0199) that the OpenADR 2.0 profiles use (2.0b section 9.3): a
// client-to-server stream with STARTTLS, SASL EXTERNAL authentication by
// X.509 client certificate (the username is the certificate's common
// name), resource binding, presence, IQ and message stanzas carrying
// OpenADR payloads, service discovery and ping. It has a Server, for
// embedding in a VTN, and a Client, for VENs and tests.
//
// Written on encoding/xml and crypto/tls from the RFCs and XEPs; no
// third-party XMPP library is used.
package xmpp

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// Namespaces.
const (
	NSClient  = "jabber:client"
	NSStream  = "http://etherx.jabber.org/streams"
	NSTLS     = "urn:ietf:params:xml:ns:xmpp-tls"
	NSSASL    = "urn:ietf:params:xml:ns:xmpp-sasl"
	NSBind    = "urn:ietf:params:xml:ns:xmpp-bind"
	NSSession = "urn:ietf:params:xml:ns:xmpp-session"
	NSStanzas = "urn:ietf:params:xml:ns:xmpp-stanzas"
	NSPing    = "urn:xmpp:ping"
	NSDiscoI  = "http://jabber.org/protocol/disco#info"
	NSDiscoIt = "http://jabber.org/protocol/disco#items"
	NSRoster  = "jabber:iq:roster"
	// FeatureOpenADR is the disco feature of an OpenADR 2.0 server
	// (2.0b section 9.3.4.9.1).
	FeatureOpenADR = "http://openadr.org/openadr2"
	// NodeServices is the disco node listing the OpenADR service JIDs
	// (9.3.4.9.2). The spec writes it with "openadr2" in the query and
	// "OpenADR2" in the answer; both are accepted.
	NodeServices = "http://openadr.org/openadr2#services"
	// NodeServicePrefix precedes the service name in each item's node.
	NodeServicePrefix = "http://openadr.org/OpenADR2/"
)

// Stanza is one iq, message or presence stanza.
type Stanza struct {
	Name  string // iq, message or presence
	Type  string
	ID    string
	From  string
	To    string
	Inner []byte // the child elements, as received
}

// Payload is the first child element (the OpenADR payload of an IQ).
func (s *Stanza) Payload() []byte { return bytes.TrimSpace(s.Inner) }

// ErrorCondition is the defined condition of an error stanza.
func (s *Stanza) ErrorCondition() string {
	if s.Type != "error" {
		return ""
	}
	d := xml.NewDecoder(bytes.NewReader(s.Inner))
	depth := 0
	for {
		tok, err := d.Token()
		if err != nil {
			return "undefined-condition"
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && t.Name.Space == NSStanzas {
				return t.Name.Local
			}
		case xml.EndElement:
			depth--
		}
	}
}

// StanzaError is an error stanza received for a request.
type StanzaError struct{ Condition string }

func (e *StanzaError) Error() string { return "XMPP error: " + e.Condition }

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return strings.ReplaceAll(b.String(), "'", "&#39;")
}

// stripDecl drops an XML declaration from a payload embedded in a stanza.
func stripDecl(p []byte) []byte {
	p = bytes.TrimSpace(p)
	if bytes.HasPrefix(p, []byte("<?xml")) {
		if i := bytes.Index(p, []byte("?>")); i >= 0 {
			p = bytes.TrimSpace(p[i+2:])
		}
	}
	return p
}

// render writes a stanza.
func render(s Stanza) []byte {
	var b bytes.Buffer
	b.WriteString("<" + s.Name)
	for _, a := range [][2]string{{"type", s.Type}, {"id", s.ID}, {"from", s.From}, {"to", s.To}} {
		if a[1] != "" {
			b.WriteString(" " + a[0] + "='" + esc(a[1]) + "'")
		}
	}
	if len(s.Inner) == 0 {
		b.WriteString("/>")
		return b.Bytes()
	}
	b.WriteString(">")
	b.Write(stripDecl(s.Inner))
	b.WriteString("</" + s.Name + ">")
	return b.Bytes()
}

// errorInner is the child of an error stanza.
func errorInner(typ, cond string) []byte {
	return []byte("<error type='" + typ + "'><" + cond + " xmlns='" + NSStanzas + "'/></error>")
}

// errorType is RFC 6120 8.3.3's type for a condition.
func errorType(cond string) string {
	switch cond {
	case "bad-request", "not-acceptable", "jid-malformed":
		return "modify"
	case "not-allowed", "forbidden", "not-authorized":
		return "cancel"
	case "internal-server-error", "resource-constraint":
		return "wait"
	}
	return "cancel"
}

// stream is one XML stream over a connection.
type stream struct {
	conn net.Conn
	r    *bufio.Reader
	dec  *xml.Decoder
	wmu  sync.Mutex
}

func newStream(c net.Conn) *stream {
	s := &stream{conn: c}
	s.reset()
	return s
}

// reset starts reading a new stream on the same connection (after TLS
// or SASL); the buffered reader keeps what was already read.
func (s *stream) reset() {
	if s.r == nil {
		s.r = bufio.NewReader(s.conn)
	}
	s.dec = xml.NewDecoder(s.r)
	s.dec.Strict = true
}

func (s *stream) upgrade(c net.Conn) {
	s.conn, s.r = c, bufio.NewReader(c)
	s.reset()
}

func (s *stream) write(b []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.conn.Write(b)
	return err
}

// next is the next element at stream level: the stream header itself
// (Name stream) or a top-level element; io.EOF when the stream closes.
func (s *stream) next() (xml.StartElement, error) {
	for {
		tok, err := s.dec.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			return t, nil
		case xml.EndElement:
			if t.Name.Local == "stream" {
				return xml.StartElement{}, io.EOF
			}
		}
	}
}

// raw is an element read whole.
type raw struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Inner   []byte     `xml:",innerxml"`
}

func (r *raw) attr(name string) string {
	for _, a := range r.Attrs {
		if a.Name.Local == name && a.Name.Space == "" {
			return a.Value
		}
	}
	return ""
}

func (s *stream) element(start xml.StartElement) (*raw, error) {
	var r raw
	if err := s.dec.DecodeElement(&r, &start); err != nil {
		return nil, err
	}
	return &r, nil
}

func (r *raw) stanza() *Stanza {
	return &Stanza{Name: r.XMLName.Local, Type: r.attr("type"), ID: r.attr("id"), From: r.attr("from"), To: r.attr("to"), Inner: r.Inner}
}

// child is the first child element's name.
func child(inner []byte) xml.Name {
	d := xml.NewDecoder(bytes.NewReader(inner))
	for {
		tok, err := d.Token()
		if err != nil {
			return xml.Name{}
		}
		if t, ok := tok.(xml.StartElement); ok {
			return t.Name
		}
	}
}

// header is a stream header.
func header(from, to, id string) []byte {
	h := "<?xml version='1.0'?><stream:stream xmlns='" + NSClient + "' xmlns:stream='" + NSStream + "' version='1.0'"
	if from != "" {
		h += " from='" + esc(from) + "'"
	}
	if to != "" {
		h += " to='" + esc(to) + "'"
	}
	if id != "" {
		h += " id='" + esc(id) + "'"
	}
	return []byte(h + ">")
}

// Bare is a JID without its resource.
func Bare(jid string) string {
	if i := strings.IndexByte(jid, '/'); i >= 0 {
		return jid[:i]
	}
	return jid
}

// Local is a JID's localpart.
func Local(jid string) string {
	b := Bare(jid)
	if i := strings.IndexByte(b, '@'); i >= 0 {
		return b[:i]
	}
	return ""
}

// Domain is a JID's domainpart.
func Domain(jid string) string {
	b := Bare(jid)
	if i := strings.IndexByte(b, '@'); i >= 0 {
		return b[i+1:]
	}
	return b
}

// pending waits for IQ answers by id.
type pending struct {
	mu sync.Mutex
	m  map[string]chan *Stanza
}

func (p *pending) add(id string) chan *Stanza {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]chan *Stanza{}
	}
	ch := make(chan *Stanza, 1)
	p.m[id] = ch
	return ch
}

func (p *pending) done(st *Stanza) bool {
	p.mu.Lock()
	ch := p.m[st.ID]
	delete(p.m, st.ID)
	p.mu.Unlock()
	if ch == nil {
		return false
	}
	ch <- st
	return true
}

func (p *pending) drop(id string) {
	p.mu.Lock()
	delete(p.m, id)
	p.mu.Unlock()
}

// Handler answers an IQ get/set (or a message, whose answer is dropped):
// the result's payload, or an RFC 6120 error condition.
type Handler func(st *Stanza) (payload []byte, errCondition string)

var errClosed = errors.New("xmpp: the stream is closed")

// result builds the answer to an IQ.
func result(req *Stanza, from string, payload []byte, cond string) Stanza {
	out := Stanza{Name: "iq", Type: "result", ID: req.ID, From: from, To: req.From, Inner: payload}
	if cond != "" {
		out.Type, out.Inner = "error", errorInner(errorType(cond), cond)
	}
	return out
}

// ParseStanza reads one stanza from its XML (for tests and logs).
func ParseStanza(b []byte) (*Stanza, error) {
	var r raw
	if err := xml.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	switch r.XMLName.Local {
	case "iq", "message", "presence":
	default:
		return nil, fmt.Errorf("%s is not a stanza", r.XMLName.Local)
	}
	return r.stanza(), nil
}

// ServicesOf reads a disco#items answer into service name → JID.
func ServicesOf(inner []byte) map[string]string {
	var q struct {
		Items []struct {
			JID  string `xml:"jid,attr"`
			Node string `xml:"node,attr"`
		} `xml:"item"`
	}
	out := map[string]string{}
	if xml.Unmarshal(inner, &q) != nil {
		return out
	}
	for _, it := range q.Items {
		if i := strings.LastIndexByte(it.Node, '/'); i >= 0 && strings.HasPrefix(strings.ToLower(it.Node), strings.ToLower(NodeServicePrefix)) {
			out[it.Node[i+1:]] = it.JID
		}
	}
	return out
}

// Features reads a disco#info answer's feature vars.
func Features(inner []byte) []string {
	var q struct {
		Features []struct {
			Var string `xml:"var,attr"`
		} `xml:"feature"`
	}
	_ = xml.Unmarshal(inner, &q)
	var out []string
	for _, f := range q.Features {
		out = append(out, f.Var)
	}
	return out
}
