package xmpp

// Password SASL mechanisms beside EXTERNAL: PLAIN
// (RFC 4616), SCRAM-SHA-1 (RFC 5802) and SCRAM-SHA-256 (RFC 7677),
// without channel binding (the -PLUS variants are not offered). The server
// offers them only after STARTTLS, and only when Server.Password is set;
// the client uses them only when ClientConfig.Password is set. Passwords
// are compared as given: SASLprep (RFC 4013) is not applied, so a
// password outside ASCII must be typed in the same Unicode form on both
// sides. SCRAM is github.com/cB-Sigma/iotcrypto/sasl (over
// github.com/xdg-go/scram).

import (
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/cB-Sigma/iotcrypto/sasl"
)

// SASL mechanism names.
const (
	MechExternal    = "EXTERNAL"
	MechPlain       = "PLAIN"
	MechSCRAMSHA1   = sasl.SCRAMSHA1
	MechSCRAMSHA256 = sasl.SCRAMSHA256
)

// saslError is a SASL failure condition (RFC 6120 6.5).
type saslError string

func (e saslError) Error() string { return "SASL: " + string(e) }

// plainServer checks a PLAIN message and returns the user it logs in.
func plainServer(msg []byte, password func(string) (string, bool)) (string, error) {
	parts := strings.Split(string(msg), "\x00")
	if len(parts) != 3 {
		return "", saslError("malformed-request")
	}
	authz, user, pass := parts[0], parts[1], parts[2]
	if user == "" || authz != "" && authz != user {
		return "", saslError("invalid-authzid")
	}
	want, ok := password(user)
	if !ok || want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(pass)) != 1 {
		return "", saslError("not-authorized")
	}
	return user, nil
}

// saslErr turns a shared-package SASL condition into this package's.
func saslErr(err error) error {
	var e sasl.Error
	if errors.As(err, &e) {
		return saslError(e)
	}
	return err
}

// scramServer runs the server side of SCRAM (internal/sasl). first is the
// client's first message; exchange sends a challenge and returns the
// client's response. It returns the user and the final server message.
func scramServer(mech string, first []byte, password func(string) (string, bool),
	exchange func(challenge []byte) ([]byte, error)) (string, []byte, error) {
	u, fin, err := sasl.Server(mech, first, password, exchange)
	return u, fin, saslErr(err)
}

// scramClient runs the client side of SCRAM over exchange (internal/sasl).
func scramClient(mech, user, password string, exchange func(msg []byte, last bool) ([]byte, error)) error {
	return saslErr(sasl.Client(mech, user, password, exchange))
}
