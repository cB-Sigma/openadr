package oadr2b

// TLS settings of both kinds (2.0b profile, section 10.4 and conformance
// rules 67 and 68).
//
// Rule 67 makes TLS 1.2 with two cipher suites the default behaviour of
// every VTN and VEN, as client and as server:
// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (ECC certificates) and
// TLS_RSA_WITH_AES_128_CBC_SHA256 (RSA certificates). A server must pick
// one of them whatever else the client offers, and a VTN client must offer
// both. Go's crypto/tls implements both suites but leaves them out of its
// default list (CBC-SHA256 suites, and RSA key exchange since Go 1.22);
// naming them in tls.Config.CipherSuites enables them without any GODEBUG
// setting (GODEBUG tlsrsakex only changes the default list). TLS 1.3 has
// its own, non-configurable suites, so the openadr profile caps the
// version at TLS 1.2.
//
// Setting tlsProfile:
//
//	compatible  (default) TLS 1.2 and 1.3; the mandated suites plus Go's
//	            secure suites, so peers that do not offer the two CBC
//	            suites (most current TLS stacks) still connect
//	openadr     TLS 1.2 only, exactly the two mandated suites: for
//	            certification testing
//
// Rule 68: RSA keys of at least 2048 bits and ECC keys of at least 224
// bits; a VTN supports both an ECC and an RSA certificate (setting
// certificates adds pairs beside cert/key, and Go presents the one that
// matches the suite the client offers).

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// TLS profiles (setting tlsProfile).
const (
	TLSProfileOpenADR    = "openadr"
	TLSProfileCompatible = "compatible"
)

// MandatedCipherSuites are the 2.0b default suites (rule 67).
var MandatedCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
}

// ApplyTLSProfile sets versions and suites on c.
func ApplyTLSProfile(c *tls.Config, profile string) error {
	switch profile {
	case TLSProfileOpenADR:
		c.MinVersion, c.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
		c.CipherSuites = append([]uint16(nil), MandatedCipherSuites...)
	case "", TLSProfileCompatible:
		c.MinVersion, c.MaxVersion = tls.VersionTLS12, 0
		c.CipherSuites = append([]uint16(nil), MandatedCipherSuites...)
		for _, s := range tls.CipherSuites() {
			c.CipherSuites = append(c.CipherSuites, s.ID)
		}
	default:
		return fmt.Errorf("tlsProfile %q is not openadr or compatible", profile)
	}
	return nil
}

// CheckKeySize applies rule 68's minimum key lengths to a certificate.
func CheckKeySize(c tls.Certificate) error {
	if len(c.Certificate) == 0 {
		return fmt.Errorf("the certificate is empty")
	}
	leaf := c.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(c.Certificate[0]); err != nil {
			return err
		}
	}
	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("an RSA key of %d bits is below the 2048 bits OpenADR requires", k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 224 {
			return fmt.Errorf("an ECC key of %d bits is below the 224 bits OpenADR requires", k.Curve.Params().BitSize)
		}
	default:
		return fmt.Errorf("certificate key type %T is not RSA or ECC", k)
	}
	return nil
}

// KeyKind is "rsa" or "ecc".
func KeyKind(c tls.Certificate) string {
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return ""
	}
	if _, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
		return "rsa"
	}
	return "ecc"
}

// CertPair is one more certificate and key (setting certificates).
type CertPair struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// LoadCertificates loads cert/key and the extra pairs, checking key sizes.
func LoadCertificates(cert, key string, extra []CertPair) ([]tls.Certificate, error) {
	var out []tls.Certificate
	for i, p := range append([]CertPair{{cert, key}}, extra...) {
		pair, err := LoadKeyPair(p.Cert, p.Key)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i+1, err)
		}
		if err := CheckKeySize(pair); err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i+1, err)
		}
		out = append(out, pair)
	}
	return out, nil
}

// PEMOrFile reads v as PEM when it holds a PEM block, else as a file path;
// what names the item in errors.
func PEMOrFile(v, what string) ([]byte, error) {
	if strings.Contains(v, "-----BEGIN") {
		return []byte(v), nil
	}
	b, err := os.ReadFile(v)
	if err != nil {
		return nil, fmt.Errorf("reading the %s: %w", what, err)
	}
	return b, nil
}

// LoadKeyPair loads a certificate and key, each PEM or a file path.
func LoadKeyPair(certV, keyV string) (tls.Certificate, error) {
	c, err := PEMOrFile(certV, "certificate")
	if err != nil {
		return tls.Certificate{}, err
	}
	k, err := PEMOrFile(keyV, "private key")
	if err != nil {
		return tls.Certificate{}, err
	}
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("the VTN certificate and key: %w", err)
	}
	return pair, nil
}
