package xmpp

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func unmarshalInner(inner []byte, v any) error { return xml.Unmarshal(inner, v) }

// ClientConfig configures a client.
type ClientConfig struct {
	// Addr is host:port of the server (default port 5222).
	Addr string
	// Domain is the XMPP domain; ServerName (TLS) defaults to it.
	Domain string
	// Resource is bound as the JID's resource (9.3.4.1: VENs always use a
	// fixed resource; default "client").
	Resource string
	// TLS holds the client certificate and the CAs of the server.
	TLS *tls.Config
	// Handle answers IQs the server sends (nil: service-unavailable).
	Handle Handler
	// Username and Password log in with a password mechanism (the best
	// the server offers of SCRAM-SHA-256, SCRAM-SHA-1 and PLAIN, only
	// after TLS) instead of SASL EXTERNAL. Username is the JID's local
	// part.
	Username string
	Password string
}

// Client is an authenticated, bound XMPP client.
type Client struct {
	cfg    ClientConfig
	st     *stream
	jid    string
	wait   pending
	done   chan struct{}
	once   sync.Once
	closed bool
	mu     sync.Mutex
}

// Dial connects, negotiates STARTTLS, SASL EXTERNAL and the resource, and
// sends the initial presence (9.3.4.5).
func Dial(ctx context.Context, cfg ClientConfig) (*Client, error) {
	if cfg.Resource == "" {
		cfg.Resource = "client"
	}
	addr := cfg.Addr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "5222")
	}
	var dialer net.Dialer
	c, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	}
	cl := &Client{cfg: cfg, st: newStream(c), done: make(chan struct{})}
	if err := cl.negotiate(c); err != nil {
		_ = c.Close()
		return nil, err
	}
	_ = cl.st.conn.SetDeadline(time.Time{})
	go cl.read()
	if err := cl.st.write([]byte("<presence/>")); err != nil {
		_ = cl.st.conn.Close()
		return nil, err
	}
	return cl, nil
}

func (cl *Client) open() error {
	_, err := cl.openFeatures()
	return err
}

// openFeatures opens a stream and returns the server's stream features.
func (cl *Client) openFeatures() (*raw, error) {
	var none *raw
	if err := cl.st.write(header("", cl.cfg.Domain, "")); err != nil {
		return none, err
	}
	start, err := cl.st.next()
	if err != nil {
		return none, err
	}
	if start.Name.Local != "stream" {
		return none, errors.New("the server did not open a stream")
	}
	start, err = cl.st.next()
	if err != nil {
		return none, err
	}
	if start.Name.Local == "error" {
		return none, errors.New("the server refused the stream")
	}
	if start.Name.Local != "features" {
		return none, fmt.Errorf("expected stream features, got %s", start.Name.Local)
	}
	return cl.st.element(start)
}

func (cl *Client) negotiate(c net.Conn) error {
	if err := cl.open(); err != nil {
		return err
	}
	if err := cl.st.write([]byte("<starttls xmlns='" + NSTLS + "'/>")); err != nil {
		return err
	}
	start, err := cl.st.next()
	if err != nil {
		return err
	}
	if start.Name.Local != "proceed" {
		return errors.New("the server did not accept STARTTLS")
	}
	if _, err := cl.st.element(start); err != nil {
		return err
	}
	tcfg := cl.cfg.TLS.Clone()
	if tcfg.ServerName == "" {
		host, _, _ := net.SplitHostPort(cl.cfg.Addr)
		if host == "" || net.ParseIP(host) == nil {
			tcfg.ServerName = cl.cfg.Domain
		} else {
			tcfg.ServerName = host
		}
	}
	tc := tls.Client(c, tcfg)
	if err := tc.Handshake(); err != nil {
		return fmt.Errorf("TLS: %w", err)
	}
	cl.st.upgrade(tc)
	feats, err := cl.openFeatures()
	if err != nil {
		return err
	}
	if cl.cfg.Password != "" {
		if err := cl.passwordAuth(feats); err != nil {
			return err
		}
		return cl.bind()
	}
	// SASL EXTERNAL; the authorisation identity is left to the server,
	// which takes the certificate's common name (9.3.4.7).
	if err := cl.st.write([]byte("<auth xmlns='" + NSSASL + "' mechanism='EXTERNAL'>=</auth>")); err != nil {
		return err
	}
	start, err = cl.st.next()
	if err != nil {
		return err
	}
	r, err := cl.st.element(start)
	if err != nil {
		return err
	}
	if r.XMLName.Local != "success" {
		return fmt.Errorf("SASL EXTERNAL refused: %s", child(r.Inner).Local)
	}
	return cl.bind()
}

// bind restarts the stream after SASL and binds the resource.
func (cl *Client) bind() error {
	cl.st.reset()
	if err := cl.open(); err != nil {
		return err
	}
	id := newID()
	if err := cl.st.write(render(Stanza{Name: "iq", Type: "set", ID: id,
		Inner: []byte("<bind xmlns='" + NSBind + "'><resource>" + esc(cl.cfg.Resource) + "</resource></bind>")})); err != nil {
		return err
	}
	start, err := cl.st.next()
	if err != nil {
		return err
	}
	r, err := cl.st.element(start)
	if err != nil {
		return err
	}
	st := r.stanza()
	if st.Type != "result" || st.ID != id {
		return errors.New("resource binding refused")
	}
	var bind struct {
		JID string `xml:"jid"`
	}
	if err := unmarshalInner(st.Inner, &bind); err != nil || bind.JID == "" {
		return errors.New("resource binding gave no JID")
	}
	cl.jid = bind.JID
	return nil
}

// JID is the bound full JID.
func (cl *Client) JID() string { return cl.jid }

// Done is closed when the stream ends.
func (cl *Client) Done() <-chan struct{} { return cl.done }

func (cl *Client) read() {
	defer cl.once.Do(func() { close(cl.done) })
	for {
		start, err := cl.st.next()
		if err != nil {
			return
		}
		r, err := cl.st.element(start)
		if err != nil {
			return
		}
		st := r.stanza()
		switch st.Name {
		case "iq":
			if st.Type == "result" || st.Type == "error" {
				cl.wait.done(st)
				continue
			}
			go cl.answer(st)
		case "message":
			if cl.cfg.Handle != nil {
				go cl.cfg.Handle(st)
			}
		}
	}
}

func (cl *Client) answer(st *Stanza) {
	name := child(st.Inner)
	var payload []byte
	cond := ""
	switch {
	case name.Space == NSPing:
	case name.Space == NSDiscoI && st.Type == "get":
		// A VEN supporting disco announces the OpenADR feature (9.3.4.9.3).
		payload = []byte("<query xmlns='" + NSDiscoI + "'><feature var='" + FeatureOpenADR + "'/><feature var='" + NSDiscoI + "'/></query>")
	case cl.cfg.Handle != nil:
		payload, cond = cl.cfg.Handle(st)
	default:
		cond = "service-unavailable"
	}
	_ = cl.st.write(render(result(st, cl.jid, payload, cond)))
}

// IQ sends an IQ and waits for the answer; an error stanza is a
// *StanzaError.
func (cl *Client) IQ(ctx context.Context, to, typ string, payload []byte) (*Stanza, error) {
	id := newID()
	ch := cl.wait.add(id)
	defer cl.wait.drop(id)
	if err := cl.st.write(render(Stanza{Name: "iq", Type: typ, ID: id, To: to, Inner: payload})); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-cl.done:
		return nil, errClosed
	case ans := <-ch:
		if ans.Type == "error" {
			return ans, &StanzaError{Condition: ans.ErrorCondition()}
		}
		return ans, nil
	}
}

// Ping sends an XEP-0199 ping to the server (9.3.4.6).
func (cl *Client) Ping(ctx context.Context) error {
	_, err := cl.IQ(ctx, cl.cfg.Domain, "get", []byte("<ping xmlns='"+NSPing+"'/>"))
	return err
}

// Services discovers the OpenADR service JIDs (9.3.4.9): the domain must
// announce the OpenADR feature; the result maps service name (EiEvent, …)
// to JID.
func (cl *Client) Services(ctx context.Context) (map[string]string, error) {
	info, err := cl.IQ(ctx, cl.cfg.Domain, "get", []byte("<query xmlns='"+NSDiscoI+"'/>"))
	if err != nil {
		return nil, err
	}
	var q struct {
		Features []struct {
			Var string `xml:"var,attr"`
		} `xml:"feature"`
		Items []struct {
			JID  string `xml:"jid,attr"`
			Node string `xml:"node,attr"`
		} `xml:"item"`
	}
	if err := unmarshalInner(info.Inner, &q); err != nil {
		return nil, err
	}
	found := false
	for _, f := range q.Features {
		found = found || f.Var == FeatureOpenADR
	}
	if !found {
		return nil, errors.New("the XMPP server does not announce OpenADR")
	}
	items, err := cl.IQ(ctx, cl.cfg.Domain, "get", []byte("<query xmlns='"+NSDiscoIt+"' node='"+NodeServices+"'/>"))
	if err != nil {
		return nil, err
	}
	q.Items = nil
	if err := unmarshalInner(items.Inner, &q); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, it := range q.Items {
		// Nodes are http://openadr.org/OpenADR2/<service> (any case).
		if i := strings.LastIndexByte(it.Node, '/'); i >= 0 && strings.HasPrefix(strings.ToLower(it.Node), strings.ToLower(NodeServicePrefix)) {
			out[it.Node[i+1:]] = it.JID
		}
	}
	if len(out) == 0 {
		return nil, errors.New("the XMPP server lists no OpenADR services")
	}
	return out, nil
}

// Close sends unavailable presence (9.3.4.5), ends the stream and closes
// the connection.
func (cl *Client) Close() error {
	cl.mu.Lock()
	if cl.closed {
		cl.mu.Unlock()
		return nil
	}
	cl.closed = true
	cl.mu.Unlock()
	_ = cl.st.write([]byte("<presence type='unavailable'/></stream:stream>"))
	select {
	case <-cl.done:
	case <-time.After(time.Second):
	}
	return cl.st.conn.Close()
}

// TLS is the stream's TLS connection state.
func (cl *Client) TLS() *tls.ConnectionState {
	if tc, ok := cl.st.conn.(*tls.Conn); ok {
		st := tc.ConnectionState()
		return &st
	}
	return nil
}

// Message sends a message stanza (no answer), for operations that need
// no response (9.3.4.3).
func (cl *Client) Message(to string, payload []byte) error {
	return cl.st.write(render(Stanza{Name: "message", Type: "normal", ID: newID(), To: to, Inner: payload}))
}

// passwordAuth logs in with the best password mechanism feats offers.
func (cl *Client) passwordAuth(feats *raw) error {
	var list struct {
		Mechanisms []string `xml:"mechanisms>mechanism"`
	}
	_ = unmarshalInner([]byte("<f>"+string(feats.Inner)+"</f>"), &list)
	offered := map[string]bool{}
	for _, m := range list.Mechanisms {
		offered[strings.TrimSpace(m)] = true
	}
	mech := ""
	for _, m := range []string{MechSCRAMSHA256, MechSCRAMSHA1, MechPlain} {
		if offered[m] {
			mech = m
			break
		}
	}
	if mech == "" {
		return fmt.Errorf("the server offers no password mechanism (it offers %s)", strings.Join(list.Mechanisms, ", "))
	}
	// read is the server's next SASL element: a challenge's or the
	// success's data, or an error for a failure.
	read := func() (string, []byte, error) {
		start, err := cl.st.next()
		if err != nil {
			return "", nil, err
		}
		r, err := cl.st.element(start)
		if err != nil {
			return "", nil, err
		}
		if r.XMLName.Local == "failure" {
			return "", nil, fmt.Errorf("SASL %s refused: %s", mech, child(r.Inner).Local)
		}
		b, err := unb64(r.Inner)
		return r.XMLName.Local, b, err
	}
	if mech == MechPlain {
		msg := "\x00" + cl.cfg.Username + "\x00" + cl.cfg.Password
		if err := cl.st.write([]byte("<auth xmlns='" + NSSASL + "' mechanism='PLAIN'>" + b64([]byte(msg)) + "</auth>")); err != nil {
			return err
		}
		if el, _, err := read(); err != nil {
			return err
		} else if el != "success" {
			return fmt.Errorf("SASL PLAIN: unexpected %s", el)
		}
		return nil
	}
	step := 0
	return scramClient(mech, cl.cfg.Username, cl.cfg.Password, func(msg []byte, last bool) ([]byte, error) {
		var out string
		if step == 0 {
			out = "<auth xmlns='" + NSSASL + "' mechanism='" + mech + "'>" + b64(msg) + "</auth>"
		} else {
			out = "<response xmlns='" + NSSASL + "'>" + b64(msg) + "</response>"
		}
		step++
		if err := cl.st.write([]byte(out)); err != nil {
			return nil, err
		}
		el, data, err := read()
		if err != nil {
			return nil, err
		}
		if last && el != "success" || !last && el != "challenge" {
			return nil, fmt.Errorf("SASL %s: unexpected %s", mech, el)
		}
		return data, nil
	})
}
