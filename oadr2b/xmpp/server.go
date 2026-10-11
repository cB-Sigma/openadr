package xmpp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// Item is a disco#items entry: a service JID and its node.
type Item struct {
	JID  string
	Node string
}

// Server is a minimal XMPP server for one domain: clients authenticate
// with SASL EXTERNAL after STARTTLS (TLS is required), or with a password
// (SCRAM-SHA-256, SCRAM-SHA-1 or PLAIN, sasl.go) when Password is set,
// bind a resource and exchange stanzas with the server's own services. Stanzas between clients
// are refused (2.0b section 9.3.4.1: VEN-to-VEN traffic is filtered).
type Server struct {
	Domain string
	// TLS is the server's TLS configuration; it must ask for and verify
	// client certificates (SASL EXTERNAL uses them). With Password set it
	// may make them optional (tls.VerifyClientCertIfGiven).
	TLS *tls.Config
	// Accept decides whether an authenticated certificate may log in.
	Accept func(cert *x509.Certificate) error
	// Password, when set, also offers the password mechanisms after TLS:
	// it returns the password of a user (the JID's local part), and false
	// for a user who may not log in with one.
	Password func(user string) (string, bool)
	// Services are the JIDs (besides Domain) handled by Handle.
	Services []Item
	// Handle answers IQs and messages sent to the domain or a service JID
	// (other than discovery and ping, answered here).
	Handle func(sess *Session, st *Stanza) (payload []byte, errCondition string)
	// Presence reports a session's availability.
	Presence func(sess *Session, available bool)
	Log      *slog.Logger

	mu       sync.Mutex
	sessions map[string]*Session // full JID → session
	ln       net.Listener
	closed   bool
}

// Session is one authenticated, bound client.
type Session struct {
	JID string
	// Cert is the client certificate (nil when the client logged in with
	// a password and gave none).
	Cert *x509.Certificate
	// Mechanism is the SASL mechanism the client logged in with.
	Mechanism string
	srv       *Server
	st        *stream
	wait      pending
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	if s.sessions == nil {
		s.sessions = map[string]*Session{}
	}
	s.mu.Unlock()
	if s.Log == nil {
		s.Log = slog.Default()
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go s.serveConn(c)
	}
}

// Close stops the server and ends every session.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	var all []*Session
	for _, x := range s.sessions {
		all = append(all, x)
	}
	s.mu.Unlock()
	for _, x := range all {
		_ = x.st.write([]byte("</stream:stream>"))
		_ = x.st.conn.Close()
	}
	if ln != nil {
		return ln.Close()
	}
	return nil
}

// Session is the bound session of a full JID (nil when offline).
func (s *Server) Session(jid string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[jid]
}

// Sessions lists the bound full JIDs.
func (s *Server) Sessions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for j := range s.sessions {
		out = append(out, j)
	}
	return out
}

// IQ sends an IQ from the domain to a bound session and waits for its
// answer; an error stanza is a *StanzaError.
func (s *Server) IQ(ctx context.Context, from, to, typ string, payload []byte) (*Stanza, error) {
	sess := s.Session(to)
	if sess == nil {
		return nil, fmt.Errorf("xmpp: %s is not online", to)
	}
	if from == "" {
		from = s.Domain
	}
	id := newID()
	ch := sess.wait.add(id)
	defer sess.wait.drop(id)
	if err := sess.st.write(render(Stanza{Name: "iq", Type: typ, ID: id, From: from, To: to, Inner: payload})); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ans := <-ch:
		if ans.Type == "error" {
			return ans, &StanzaError{Condition: ans.ErrorCondition()}
		}
		return ans, nil
	}
}

// Message sends a message stanza (no answer) to a bound session.
func (s *Server) Message(from, to string, payload []byte) error {
	sess := s.Session(to)
	if sess == nil {
		return fmt.Errorf("xmpp: %s is not online", to)
	}
	if from == "" {
		from = s.Domain
	}
	return sess.st.write(render(Stanza{Name: "message", Type: "normal", ID: newID(), From: from, To: to, Inner: payload}))
}

func (s *Server) local(to string) bool {
	if to == "" || to == s.Domain {
		return true
	}
	for _, it := range s.Services {
		if to == it.JID || Bare(to) == Bare(it.JID) {
			return true
		}
	}
	return false
}

func (s *Server) serveConn(c net.Conn) {
	defer c.Close()
	sess, err := s.negotiate(c)
	if err != nil {
		s.Log.Warn("XMPP session refused", "remote", c.RemoteAddr().String(), "error", err)
		return
	}
	s.Log.Info("XMPP session bound", "jid", sess.JID)
	defer func() {
		s.mu.Lock()
		if s.sessions[sess.JID] == sess {
			delete(s.sessions, sess.JID)
		}
		s.mu.Unlock()
		if s.Presence != nil {
			s.Presence(sess, false)
		}
	}()
	for {
		start, err := sess.st.next()
		if err != nil {
			return
		}
		r, err := sess.st.element(start)
		if err != nil {
			return
		}
		st := r.stanza()
		st.From = sess.JID // the server stamps the sender (RFC 6120 8.1.2.1)
		switch st.Name {
		case "presence":
			if st.To == "" && s.Presence != nil {
				s.Presence(sess, st.Type != "unavailable")
			}
		case "iq":
			if st.Type == "result" || st.Type == "error" {
				sess.wait.done(st)
				continue
			}
			go sess.answer(st)
		case "message":
			if s.local(st.To) && s.Handle != nil {
				go s.Handle(sess, st)
			}
		}
	}
}

// answer handles one IQ get/set from a client.
func (sess *Session) answer(st *Stanza) {
	s := sess.srv
	from := st.To
	if from == "" {
		from = s.Domain
	}
	reply := func(payload []byte, cond string) {
		_ = sess.st.write(render(result(st, from, payload, cond)))
	}
	if !s.local(st.To) {
		reply(nil, "service-unavailable") // no client-to-client traffic
		return
	}
	name := child(st.Inner)
	switch {
	case name.Space == NSPing && name.Local == "ping":
		reply(nil, "")
	case name.Space == NSSession:
		reply(nil, "")
	case name.Space == NSRoster:
		// Rosters have no role in OpenADR (9.3.4.8): an empty roster.
		reply([]byte("<query xmlns='"+NSRoster+"'/>"), "")
	case name.Space == NSDiscoI && st.Type == "get":
		reply([]byte("<query xmlns='"+NSDiscoI+"'><identity category='server' type='im' name='OpenADR VTN'/><feature var='"+
			FeatureOpenADR+"'/><feature var='"+NSDiscoI+"'/><feature var='"+NSDiscoIt+"'/><feature var='"+NSPing+"'/></query>"), "")
	case name.Space == NSDiscoIt && st.Type == "get":
		var b strings.Builder
		b.WriteString("<query xmlns='" + NSDiscoIt + "' node='" + NodeServices + "'>")
		for _, it := range s.Services {
			b.WriteString("<item jid='" + esc(it.JID) + "' node='" + esc(it.Node) + "'/>")
		}
		b.WriteString("</query>")
		reply([]byte(b.String()), "")
	case s.Handle != nil && st.Type == "set":
		p, cond := s.Handle(sess, st)
		reply(p, cond)
	default:
		reply(nil, "feature-not-implemented")
	}
}

// negotiate runs STARTTLS, SASL EXTERNAL and resource binding.
func (s *Server) negotiate(c net.Conn) (*Session, error) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	st := newStream(c)
	open := func() error {
		start, err := st.next()
		if err != nil {
			return err
		}
		if start.Name.Local != "stream" || start.Name.Space != NSStream {
			return errors.New("not an XMPP stream")
		}
		for _, a := range start.Attr {
			if a.Name.Local == "to" && a.Value != s.Domain {
				_ = st.write(append(header(s.Domain, "", newID()), []byte("<stream:error><host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>")...))
				return fmt.Errorf("stream to %s, not %s", a.Value, s.Domain)
			}
		}
		return st.write(header(s.Domain, "", newID()))
	}
	// 1. TLS is required (9.3.4.7 and RFC 6120 5).
	if err := open(); err != nil {
		return nil, err
	}
	if err := st.write([]byte("<stream:features><starttls xmlns='" + NSTLS + "'><required/></starttls></stream:features>")); err != nil {
		return nil, err
	}
	start, err := st.next()
	if err != nil {
		return nil, err
	}
	if start.Name.Space != NSTLS || start.Name.Local != "starttls" {
		return nil, errors.New("the client did not start TLS")
	}
	if _, err := st.element(start); err != nil {
		return nil, err
	}
	if err := st.write([]byte("<proceed xmlns='" + NSTLS + "'/>")); err != nil {
		return nil, err
	}
	tc := tls.Server(c, s.TLS)
	if err := tc.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS: %w", err)
	}
	st.upgrade(tc)
	certs := tc.ConnectionState().PeerCertificates
	// 2. SASL, only now that TLS is up: EXTERNAL with the client
	// certificate, and the password mechanisms when Password is set.
	if err := open(); err != nil {
		return nil, err
	}
	mechs := []string{MechExternal}
	if s.Password != nil {
		mechs = append(mechs, MechSCRAMSHA256, MechSCRAMSHA1, MechPlain)
	}
	var feat strings.Builder
	feat.WriteString("<stream:features><mechanisms xmlns='" + NSSASL + "'>")
	for _, m := range mechs {
		feat.WriteString("<mechanism>" + m + "</mechanism>")
	}
	feat.WriteString("</mechanisms></stream:features>")
	if err := st.write([]byte(feat.String())); err != nil {
		return nil, err
	}
	start, err = st.next()
	if err != nil {
		return nil, err
	}
	r, err := st.element(start)
	if err != nil {
		return nil, err
	}
	failure := func(cond string) error {
		_ = st.write([]byte("<failure xmlns='" + NSSASL + "'><" + cond + "/></failure>"))
		return errors.New("SASL: " + cond)
	}
	if r.XMLName.Space != NSSASL || r.XMLName.Local != "auth" {
		return nil, failure("malformed-request")
	}
	mech := r.attr("mechanism")
	offered := false
	for _, m := range mechs {
		offered = offered || m == mech
	}
	if !offered {
		return nil, failure("invalid-mechanism")
	}
	var cert *x509.Certificate
	if len(certs) > 0 {
		cert = certs[0]
	}
	var user string
	if mech == MechExternal {
		if cert == nil {
			return nil, failure("not-authorized")
		}
		user = cert.Subject.CommonName
		if authz := strings.TrimSpace(string(r.Inner)); authz != "" && authz != "=" {
			b, err := base64.StdEncoding.DecodeString(authz)
			if err != nil {
				return nil, failure("incorrect-encoding")
			}
			// 9.3.4.7: the username must be the certificate's common name.
			if Local(string(b)) != user || Domain(string(b)) != s.Domain {
				return nil, failure("invalid-authzid")
			}
		}
		if user == "" || strings.ContainsAny(user, "@/ ") {
			return nil, failure("not-authorized")
		}
		if s.Accept != nil {
			if err := s.Accept(cert); err != nil {
				_ = failure("not-authorized")
				return nil, err
			}
		}
		if err := st.write([]byte("<success xmlns='" + NSSASL + "'/>")); err != nil {
			return nil, err
		}
	} else {
		var final []byte
		if user, final, err = s.passwordAuth(st, mech, r.Inner); err != nil {
			var se saslError
			if errors.As(err, &se) {
				return nil, failure(string(se))
			}
			return nil, err
		}
		if user == "" || strings.ContainsAny(user, "@/ ") {
			return nil, failure("not-authorized")
		}
		if err := st.write([]byte("<success xmlns='" + NSSASL + "'>" + b64(final) + "</success>")); err != nil {
			return nil, err
		}
	}
	// 3. Resource binding.
	st.reset()
	if err := open(); err != nil {
		return nil, err
	}
	if err := st.write([]byte("<stream:features><bind xmlns='" + NSBind + "'/><session xmlns='" + NSSession + "'><optional/></session></stream:features>")); err != nil {
		return nil, err
	}
	start, err = st.next()
	if err != nil {
		return nil, err
	}
	r, err = st.element(start)
	if err != nil {
		return nil, err
	}
	req := r.stanza()
	if req.Name != "iq" || req.Type != "set" || child(req.Inner).Space != NSBind {
		return nil, errors.New("expected resource binding")
	}
	var bind struct {
		Resource string `xml:"resource"`
	}
	_ = unmarshalInner(req.Inner, &bind)
	res := strings.TrimSpace(bind.Resource)
	if res == "" {
		res = newID()
	}
	sess := &Session{JID: user + "@" + s.Domain + "/" + res, Cert: cert, Mechanism: mech, srv: s, st: st}
	s.mu.Lock()
	if old := s.sessions[sess.JID]; old != nil {
		// RFC 6120 7.7.2.2: the new session replaces the old one.
		_ = old.st.write([]byte("<stream:error><conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/></stream:error></stream:stream>"))
		_ = old.st.conn.Close()
	}
	s.sessions[sess.JID] = sess
	s.mu.Unlock()
	if err := st.write(render(Stanza{Name: "iq", Type: "result", ID: req.ID,
		Inner: []byte("<bind xmlns='" + NSBind + "'><jid>" + esc(sess.JID) + "</jid></bind>")})); err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Time{})
	return sess, nil
}

// b64 is SASL data in base64 ("=" for empty data, RFC 6120 6.4.2).
func b64(b []byte) string {
	if len(b) == 0 {
		return "="
	}
	return base64.StdEncoding.EncodeToString(b)
}

// unb64 decodes SASL data ("=" or nothing is empty).
func unb64(inner []byte) ([]byte, error) {
	v := strings.TrimSpace(string(inner))
	if v == "" || v == "=" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, saslError("incorrect-encoding")
	}
	return b, nil
}

// passwordAuth runs PLAIN or SCRAM from the <auth> element's data and
// returns the user and the success data.
func (s *Server) passwordAuth(st *stream, mech string, inner []byte) (string, []byte, error) {
	first, err := unb64(inner)
	if err != nil {
		return "", nil, err
	}
	if len(first) == 0 {
		// RFC 6120 6.4.2: no initial response; ask for it.
		if first, err = s.saslStep(st, nil); err != nil {
			return "", nil, err
		}
	}
	if mech == MechPlain {
		user, err := plainServer(first, s.Password)
		return user, nil, err
	}
	return scramServer(mech, first, s.Password, func(ch []byte) ([]byte, error) { return s.saslStep(st, ch) })
}

// saslStep sends a challenge and reads the client's response.
func (s *Server) saslStep(st *stream, challenge []byte) ([]byte, error) {
	if err := st.write([]byte("<challenge xmlns='" + NSSASL + "'>" + b64(challenge) + "</challenge>")); err != nil {
		return nil, err
	}
	start, err := st.next()
	if err != nil {
		return nil, err
	}
	r, err := st.element(start)
	if err != nil {
		return nil, err
	}
	if r.XMLName.Space != NSSASL {
		return nil, saslError("malformed-request")
	}
	switch r.XMLName.Local {
	case "response":
		return unb64(r.Inner)
	case "abort":
		return nil, saslError("aborted")
	}
	return nil, saslError("malformed-request")
}
