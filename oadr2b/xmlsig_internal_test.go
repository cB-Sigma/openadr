package oadr2b

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

func testPair(t *testing.T) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "signer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// signFigure23 signs doc in the layout of the 2.0b spec's Figure 23: an
// unqualified Id on oadrSignedObject, references without transforms
// (canonical XML 1.0 by default), the second reference naming the
// ds:Object that holds the ReplayProtect property, excAlg choosing the
// SignedInfo canonicalisation.
func signFigure23(t *testing.T, pair tls.Certificate, doc []byte, excAlg string, ts time.Time) []byte {
	t.Helper()
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		t.Fatal(err)
	}
	root, so, err := payloadParts(d)
	if err != nil {
		t.Fatal(err)
	}
	so.CreateAttr("Id", "signedObject")
	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", NSDs)
	root.InsertChildAt(so.Index(), sig)
	si := sig.CreateElement("ds:SignedInfo")
	sv := sig.CreateElement("ds:SignatureValue")
	sig.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").SetText(base64.StdEncoding.EncodeToString(pair.Certificate[0]))
	obj := sig.CreateElement("ds:Object")
	obj.CreateAttr("Id", "prop")
	sps := obj.CreateElement("ds:SignatureProperties")
	sps.CreateAttr("xmlns:dsp", NSDsp)
	rp := sps.CreateElement("ds:SignatureProperty").CreateElement("dsp:ReplayProtect")
	rp.CreateElement("dsp:timestamp").SetText(ts.UTC().Format("2006-01-02T15:04:05.0"))
	rp.CreateElement("dsp:nonce").SetText(newNonce())
	si.CreateElement("ds:CanonicalizationMethod").CreateAttr("Algorithm", excAlg)
	si.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", AlgECDSASHA256)
	for _, ref := range []struct {
		el *etree.Element
		id string
	}{{so, "signedObject"}, {obj, "prop"}} {
		dg, err := digestOf(ref.el, AlgC14N)
		if err != nil {
			t.Fatal(err)
		}
		r := si.CreateElement("ds:Reference")
		r.CreateAttr("URI", "#"+ref.id)
		r.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", AlgSHA256)
		r.CreateElement("ds:DigestValue").SetText(base64.StdEncoding.EncodeToString(dg))
	}
	c14n, err := canonical(si, excAlg)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(c14n)
	raw, err := pair.PrivateKey.(crypto.Signer).Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if raw, err = ecdsaRaw(raw, 32); err != nil {
		t.Fatal(err)
	}
	sv.SetText(base64.StdEncoding.EncodeToString(raw))
	out, err := d.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Section 10.6 and rule 514: we sign with canonical XML 1.0 and a
// qualified oadr:Id (the schema's form); we verify the Figure 23 layout
// (unqualified Id, no transforms, the Object referenced, a timestamp
// without a zone) and exclusive canonicalisation too.
//
// Covers: SIG-IPE-2311
func TestOpenADRXMLSignatureLayouts(t *testing.T) {
	pair := testPair(t)
	doc, err := Marshal(SignedObject{Poll: &Poll{VenID: "ven-1"}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(pair)
	if err != nil {
		t.Fatal(err)
	}
	ours, err := s.Sign(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ours), `oadr:Id="`+SignedObjectID+`"`) || !strings.Contains(string(ours), AlgC14N) {
		t.Errorf("our signature layout: %s", ours)
	}
	if _, err := VerifyPayload(ours); err != nil {
		t.Errorf("our own signature: %v", err)
	}
	for _, alg := range []string{AlgC14N, AlgExcC14N} {
		fig := signFigure23(t, pair, doc, alg, time.Now())
		v, err := VerifyPayload(fig)
		if err != nil {
			t.Errorf("Figure 23 layout with %s: %v", alg, err)
			continue
		}
		if time.Since(v.Timestamp) > time.Minute {
			t.Errorf("timestamp read as %s", v.Timestamp)
		}
		// Changing the signed object breaks it.
		if _, err := VerifyPayload([]byte(strings.Replace(string(fig), "ven-1", "ven-2", 1))); err == nil {
			t.Error("a changed payload verified")
		}
	}
}
