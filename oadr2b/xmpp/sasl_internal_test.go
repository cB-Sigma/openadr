package xmpp

import (
	"errors"
	"testing"
)

// Covers: SIG-IPE-3507
// RFC 5802 (SCRAM-SHA-1) and RFC 7677 (SCRAM-SHA-256): our client and
// server agree on the right password, and the server refuses a wrong one,
// an unknown user (after a normal-looking challenge) and a channel-binding
// request it did not offer; RFC 4616 PLAIN checks the password and the
// authorisation identity.
func TestSASLPasswordMechanisms(t *testing.T) {
	users := func(u string) (string, bool) {
		if u == "ven,1" {
			return "pencil", true
		}
		return "", false
	}
	run := func(mech, user, pass string) (string, error) {
		var got string
		var serr error
		err := scramClient(mech, user, pass, func() func([]byte, bool) ([]byte, error) {
			var toServer = make(chan []byte, 1)
			var toClient = make(chan []byte, 1)
			done := make(chan struct{})
			first := true
			return func(msg []byte, last bool) ([]byte, error) {
				if first {
					first = false
					go func() {
						defer close(done)
						u, fin, e := scramServer(mech, msg, users, func(ch []byte) ([]byte, error) {
							toClient <- ch
							return <-toServer, nil
						})
						got, serr = u, e
						toClient <- fin
					}()
					return <-toClient, nil
				}
				toServer <- msg
				r := <-toClient
				<-done
				if serr != nil {
					return nil, serr
				}
				return r, nil
			}
		}())
		return got, err
	}
	for _, mech := range []string{MechSCRAMSHA1, MechSCRAMSHA256} {
		if u, err := run(mech, "ven,1", "pencil"); err != nil || u != "ven,1" {
			t.Errorf("%s: %q %v", mech, u, err)
		}
		var se saslError
		if _, err := run(mech, "ven,1", "pen"); !errors.As(err, &se) || se != "not-authorized" {
			t.Errorf("%s wrong password: %v", mech, err)
		}
		if _, err := run(mech, "nobody", "pencil"); !errors.As(err, &se) || se != "not-authorized" {
			t.Errorf("%s unknown user: %v", mech, err)
		}
		if _, _, err := scramServer(mech, []byte("p=tls-unique,,n=ven=2C1,r=abc"), users, nil); !errors.As(err, &se) || se != "invalid-mechanism" {
			t.Errorf("%s channel binding: %v", mech, err)
		}
	}
	if u, err := plainServer([]byte("\x00ven,1\x00pencil"), users); err != nil || u != "ven,1" {
		t.Errorf("PLAIN: %q %v", u, err)
	}
	if _, err := plainServer([]byte("\x00ven,1\x00x"), users); err == nil {
		t.Error("PLAIN accepted a wrong password")
	}
	if _, err := plainServer([]byte("other\x00ven,1\x00pencil"), users); err == nil {
		t.Error("PLAIN accepted another authorisation identity")
	}
}
