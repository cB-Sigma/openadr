package xmpp_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b/xmpp"
)

type pki struct {
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	n    int64
}

func newPKI(t *testing.T) *pki {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &pki{ca: ca, key: key, pool: x509.NewCertPool(), n: 1}
	p.pool.AddCert(ca)
	return p
}

func (p *pki) leaf(t *testing.T, cn string) tls.Certificate {
	p.n++
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(p.n), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// The profile's XMPP (2.0b section 9.3.4): STARTTLS required, SASL
// EXTERNAL with the certificate's common name as username, a fixed
// resource, presence, disco of the OpenADR feature and service JIDs, ping,
// IQ set both ways with error stanzas, and no client-to-client traffic.
//
// Covers: SIG-IPE-2314
func TestXMPPStreamAndStanzas(t *testing.T) {
	p := newPKI(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	presence := make(chan string, 8)
	srv := &xmpp.Server{Domain: "vtn.test",
		TLS: &tls.Config{Certificates: []tls.Certificate{p.leaf(t, "vtn.test")}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.pool, MinVersion: tls.VersionTLS12},
		Accept: func(c *x509.Certificate) error {
			if c.Subject.CommonName == "banned" {
				return errors.New("not a VEN")
			}
			return nil
		},
		Services: []xmpp.Item{{JID: "vtn.test", Node: xmpp.NodeServicePrefix + "EiEvent"}, {JID: "report.vtn.test", Node: xmpp.NodeServicePrefix + "EiReport"}},
		Handle: func(sess *xmpp.Session, st *xmpp.Stanza) ([]byte, string) {
			if strings.Contains(string(st.Payload()), "bad") {
				return nil, "bad-request"
			}
			return []byte("<echo xmlns='urn:test'>" + sess.JID + "</echo>"), ""
		},
		Presence: func(sess *xmpp.Session, on bool) {
			if on {
				presence <- "on " + sess.JID
			} else {
				presence <- "off " + sess.JID
			}
		},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dial := func(cn string, h xmpp.Handler) (*xmpp.Client, error) {
		c := p.leaf(t, cn)
		return xmpp.Dial(ctx, xmpp.ClientConfig{Addr: ln.Addr().String(), Domain: "vtn.test", Handle: h,
			TLS: &tls.Config{Certificates: []tls.Certificate{c}, RootCAs: p.pool}})
	}
	ven, err := dial("ven1", func(st *xmpp.Stanza) ([]byte, string) { return []byte("<pong xmlns='urn:test'/>"), "" })
	if err != nil {
		t.Fatal(err)
	}
	if ven.JID() != "ven1@vtn.test/client" {
		t.Errorf("JID %s", ven.JID())
	}
	if got := <-presence; got != "on ven1@vtn.test/client" {
		t.Errorf("presence %s", got)
	}
	svc, err := ven.Services(ctx)
	if err != nil || svc["EiEvent"] != "vtn.test" || svc["EiReport"] != "report.vtn.test" {
		t.Errorf("services %v %v", svc, err)
	}
	if err := ven.Ping(ctx); err != nil {
		t.Error(err)
	}
	ans, err := ven.IQ(ctx, "report.vtn.test", "set", []byte("<x xmlns='urn:test'/>"))
	if err != nil || !strings.Contains(string(ans.Payload()), "ven1@vtn.test/client") {
		t.Errorf("IQ: %v %v", ans, err)
	}
	var se *xmpp.StanzaError
	if _, err := ven.IQ(ctx, "vtn.test", "set", []byte("<bad xmlns='urn:test'/>")); !errors.As(err, &se) || se.Condition != "bad-request" {
		t.Errorf("bad request answered %v", err)
	}
	// Server to client.
	back, err := srv.IQ(ctx, "", "ven1@vtn.test/client", "set", []byte("<ping2 xmlns='urn:test'/>"))
	if err != nil || !strings.Contains(string(back.Payload()), "pong") {
		t.Errorf("server IQ: %v %v", back, err)
	}
	// No VEN to VEN.
	other, err := dial("ven2", nil)
	if err != nil {
		t.Fatal(err)
	}
	<-presence
	if _, err := other.IQ(ctx, "ven1@vtn.test/client", "set", []byte("<x xmlns='urn:test'/>")); !errors.As(err, &se) || se.Condition != "service-unavailable" {
		t.Errorf("VEN to VEN: %v", err)
	}
	// Refused certificates.
	if _, err := dial("banned", nil); err == nil {
		t.Error("a refused certificate logged in")
	}
	stranger := newPKI(t).leaf(t, "ven3")
	if _, err := xmpp.Dial(ctx, xmpp.ClientConfig{Addr: ln.Addr().String(), Domain: "vtn.test", TLS: &tls.Config{Certificates: []tls.Certificate{stranger}, RootCAs: p.pool}}); err == nil {
		t.Error("a certificate from another CA logged in")
	}
	// Closing sends unavailable presence.
	_ = ven.Close()
	if got := <-presence; got != "off ven1@vtn.test/client" {
		t.Errorf("presence %s", got)
	}
	_ = other.Close()
}

// Covers: SIG-IPE-3507
// A VEN without a client certificate logs in with a password
// (SCRAM-SHA-256 chosen over SCRAM-SHA-1 and PLAIN); password mechanisms
// are never offered before STARTTLS; a wrong password is refused.
func TestXMPPPasswordLogin(t *testing.T) {
	p := newPKI(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mechs := make(chan string, 4)
	srv := &xmpp.Server{Domain: "vtn.test",
		TLS: &tls.Config{Certificates: []tls.Certificate{p.leaf(t, "vtn.test")}, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: p.pool, MinVersion: tls.VersionTLS12},
		Password: func(u string) (string, bool) {
			if u == "ven-a" {
				return "s3cret-pass", true
			}
			return "", false
		},
		Presence: func(sess *xmpp.Session, on bool) {
			if on {
				mechs <- sess.Mechanism
			}
		},
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	// Before TLS only STARTTLS is offered.
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = raw.Write([]byte("<?xml version='1.0'?><stream:stream to='vtn.test' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'>"))
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	var pre strings.Builder
	buf := make([]byte, 4096)
	for !strings.Contains(pre.String(), "</stream:features>") {
		n, err := raw.Read(buf)
		if err != nil {
			t.Fatalf("pre-TLS features: %v (%s)", err, pre.String())
		}
		pre.Write(buf[:n])
	}
	_ = raw.Close()
	if strings.Contains(pre.String(), "mechanism") {
		t.Errorf("SASL mechanisms offered before TLS: %s", pre.String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	dial := func(user, pass string) (*xmpp.Client, error) {
		return xmpp.Dial(ctx, xmpp.ClientConfig{Addr: ln.Addr().String(), Domain: "vtn.test", Username: user, Password: pass,
			TLS: &tls.Config{RootCAs: p.pool}})
	}
	c, err := dial("ven-a", "s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if c.JID() != "ven-a@vtn.test/client" {
		t.Errorf("JID %s", c.JID())
	}
	if m := <-mechs; m != xmpp.MechSCRAMSHA256 {
		t.Errorf("mechanism %s", m)
	}
	_ = c.Close()
	if _, err := dial("ven-a", "wrong"); err == nil {
		t.Error("a wrong password logged in")
	}
	if _, err := dial("ven-b", "s3cret-pass"); err == nil {
		t.Error("a user without a password logged in")
	}
}
