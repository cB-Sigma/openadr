package oadr2b

// XML signatures of OpenADR 2.0b payloads (profile section 10.6 and
// conformance rule 514): a detached XML Signature placed inside
// oadrPayload, before its sibling oadrSignedObject, that references
// oadrSignedObject by its Id and a ReplayProtect property (timestamp and
// nonce) carried in the signature's own Object. We sign with canonical
// XML 1.0 (inclusive, rule 514's list) for SignedInfo and both references,
// SHA-256 digests (section 10.6.3) and RSA-SHA256 or ECDSA-SHA256 (r||s,
// as XML Signature writes ECDSA values); KeyInfo carries the signer's
// X.509 certificate. When checking we also accept exclusive
// canonicalisation (with or without comments), which several deployed
// implementations use, and a reference without a transform (inclusive
// canonicalisation by default).
//
// goxmldsig (Apache-2.0) supplies exclusive canonicalisation and etree
// (BSD-2) the document tree. Signing and checking are done here because
// the OpenADR layout (a signature beside the signed element, two
// references) is outside what goxmldsig's own signer and validator handle.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// NSDsp is the namespace of the OpenADR signature properties
// (ReplayProtect, timestamp, nonce).
const NSDsp = "http://openadr.org/oadr-2.0b/2012/07/xmldsig-properties"

// Algorithm identifiers written and accepted.
const (
	AlgC14N           = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	AlgC14NComments   = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	AlgExcC14NComment = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	AlgExcC14N        = "http://www.w3.org/2001/10/xml-exc-c14n#"
	AlgSHA256         = "http://www.w3.org/2001/04/xmlenc#sha256"
	AlgRSASHA256      = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	AlgECDSASHA256    = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	TypeSigProperties = "http://www.w3.org/2000/09/xmldsig#SignatureProperties"
)

// SignedObjectID is the Id given to oadrSignedObject when it has none.
const SignedObjectID = "oadrSignedObject"

// Signature modes (setting xmlSignature).
const (
	SigOff     = "off"
	SigSign    = "sign"
	SigRequire = "require"
)

// ErrUnsigned is returned by VerifyPayload for a payload without a
// signature.
var ErrUnsigned = errors.New("the payload is not signed")

// Signer signs payloads with one key and certificate.
type Signer struct {
	key    crypto.Signer
	cert   []byte // DER
	method string
	size   int // ECDSA: bytes per coordinate
	now    func() time.Time
}

// NewSigner signs with the certificate's key (RSA or ECDSA).
func NewSigner(c tls.Certificate) (*Signer, error) {
	if len(c.Certificate) == 0 {
		return nil, errors.New("the signing certificate is empty")
	}
	k, ok := c.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("the signing key cannot sign")
	}
	s := &Signer{key: k, cert: c.Certificate[0], now: time.Now}
	switch pk := k.Public().(type) {
	case *rsa.PublicKey:
		s.method = AlgRSASHA256
	case *ecdsa.PublicKey:
		s.method = AlgECDSASHA256
		s.size = (pk.Curve.Params().BitSize + 7) / 8
	default:
		return nil, fmt.Errorf("signing key type %T is not RSA or ECDSA", pk)
	}
	return s, nil
}

// Fingerprint is the signing certificate's OpenADR fingerprint.
func (s *Signer) Fingerprint() string { return Fingerprint(s.cert) }

// Certificate is the signer's certificate (DER).
func (s *Signer) Certificate() []byte { return s.cert }

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Sign returns doc (an oadrPayload document) with an XML signature added.
func (s *Signer) Sign(doc []byte) ([]byte, error) {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		return nil, err
	}
	root, so, err := payloadParts(d)
	if err != nil {
		return nil, err
	}
	if existing := childNS(root, dsig.Namespace, "Signature"); existing != nil {
		return nil, errors.New("the payload is already signed")
	}
	objID := idOf(so)
	if objID == "" {
		objID = SignedObjectID
		// The 2.0b schema qualifies local attributes
		// (attributeFormDefault qualified), so oadrSignedObject's Id is
		// oadr:Id; the spec's Figure 23 writes it unqualified, which we
		// also accept.
		so.CreateAttr(so.Space+":Id", objID)
	}
	sigID, propID := "sig-"+newNonce()[:16], "prop-"+newNonce()[:16]

	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:ds", dsig.Namespace)
	sig.CreateAttr("Id", sigID)
	root.InsertChildAt(so.Index(), sig)
	si := sig.CreateElement("ds:SignedInfo")
	sv := sig.CreateElement("ds:SignatureValue")
	sig.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(s.cert))
	prop := sig.CreateElement("ds:Object").CreateElement("ds:SignatureProperties").CreateElement("ds:SignatureProperty")
	prop.CreateAttr("Id", propID)
	prop.CreateAttr("Target", "#"+sigID)
	rp := prop.CreateElement("dsp:ReplayProtect")
	rp.CreateAttr("xmlns:dsp", NSDsp)
	rp.CreateElement("dsp:timestamp").SetText(s.now().UTC().Format("2006-01-02T15:04:05.000Z"))
	rp.CreateElement("dsp:nonce").SetText(newNonce())

	si.CreateElement("ds:CanonicalizationMethod").CreateAttr("Algorithm", AlgC14N)
	si.CreateElement("ds:SignatureMethod").CreateAttr("Algorithm", s.method)
	for _, ref := range []struct {
		el  *etree.Element
		id  string
		typ string
	}{{so, objID, ""}, {prop, propID, TypeSigProperties}} {
		dg, err := digestOf(ref.el, AlgC14N)
		if err != nil {
			return nil, err
		}
		r := si.CreateElement("ds:Reference")
		r.CreateAttr("URI", "#"+ref.id)
		if ref.typ != "" {
			r.CreateAttr("Type", ref.typ)
		}
		r.CreateElement("ds:Transforms").CreateElement("ds:Transform").CreateAttr("Algorithm", AlgC14N)
		r.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", AlgSHA256)
		r.CreateElement("ds:DigestValue").SetText(base64.StdEncoding.EncodeToString(dg))
	}
	c14n, err := canonical(si, AlgC14N)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(c14n)
	raw, err := s.key.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	if s.size > 0 {
		if raw, err = ecdsaRaw(raw, s.size); err != nil {
			return nil, err
		}
	}
	sv.SetText(base64.StdEncoding.EncodeToString(raw))
	return d.WriteToBytes()
}

// payloadParts returns oadrPayload and its one oadrSignedObject.
func payloadParts(d *etree.Document) (root, so *etree.Element, err error) {
	root = d.Root()
	if root == nil || root.Tag != "oadrPayload" || root.NamespaceURI() != NSOadr {
		return nil, nil, errors.New("not an oadrPayload document")
	}
	for _, c := range root.ChildElements() {
		if c.Tag == "oadrSignedObject" && c.NamespaceURI() == NSOadr {
			if so != nil {
				return nil, nil, errors.New("more than one oadrSignedObject")
			}
			so = c
		}
	}
	if so == nil {
		return nil, nil, errors.New("no oadrSignedObject")
	}
	return root, so, nil
}

func childNS(el *etree.Element, ns, tag string) *etree.Element {
	var found *etree.Element
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			if found != nil {
				return nil
			}
			found = c
		}
	}
	return found
}

// only is the single child ns:tag of el, or an error.
func only(el *etree.Element, ns, tag string) (*etree.Element, error) {
	var found *etree.Element
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			if found != nil {
				return nil, fmt.Errorf("more than one %s", tag)
			}
			found = c
		}
	}
	if found == nil {
		return nil, fmt.Errorf("no %s in %s", tag, el.Tag)
	}
	return found, nil
}

// idOf is an element's Id attribute, unqualified or (on OpenADR
// elements) in the OpenADR namespace.
func idOf(el *etree.Element) string {
	for _, a := range el.Attr {
		if a.Key == "Id" && (a.Space == "" || a.NamespaceURI() == NSOadr) {
			return a.Value
		}
	}
	return ""
}

// c14nAlgorithms are the canonicalisations accepted when checking.
var c14nAlgorithms = map[string]bool{AlgC14N: true, AlgC14NComments: true, AlgExcC14N: true, AlgExcC14NComment: true}

// canonical is el's canonical form under alg, with the namespaces in scope
// where it stands.
func canonical(el *etree.Element, alg string) ([]byte, error) {
	switch alg {
	case AlgC14N:
		return dsig.MakeC14N10RecCanonicalizer().Canonicalize(el)
	case AlgC14NComments:
		return dsig.MakeC14N10WithCommentsCanonicalizer().Canonicalize(el)
	case AlgExcC14N, AlgExcC14NComment:
		ctx, err := etreeutils.NSBuildParentContext(el)
		if err != nil {
			return nil, err
		}
		det, err := etreeutils.NSDetatch(ctx, el)
		if err != nil {
			return nil, err
		}
		if alg == AlgExcC14NComment {
			return dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("").Canonicalize(det)
		}
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("").Canonicalize(det)
	}
	return nil, fmt.Errorf("canonicalisation %s is not supported", alg)
}

func digestOf(el *etree.Element, alg string) ([]byte, error) {
	b, err := canonical(el, alg)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

func ecdsaRaw(der []byte, size int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("ECDSA signature: %w", err)
	}
	out := make([]byte, 2*size)
	sig.R.FillBytes(out[:size])
	sig.S.FillBytes(out[size:])
	return out, nil
}

// Verified is what a good signature says.
type Verified struct {
	Cert      *x509.Certificate
	Timestamp time.Time
	Nonce     string
}

// VerifyPayload checks doc's XML signature: its shape, both digests and
// the signature value over SignedInfo with the certificate in KeyInfo. It
// returns ErrUnsigned when there is no signature. Whether the certificate
// is the expected signer and whether the replay protection is fresh are
// for the caller (see ReplayGuard).
func VerifyPayload(doc []byte) (*Verified, error) {
	d := etree.NewDocument()
	if err := d.ReadFromBytes(doc); err != nil {
		return nil, err
	}
	root, so, err := payloadParts(d)
	if err != nil {
		return nil, err
	}
	var sig *etree.Element
	for _, c := range root.ChildElements() {
		if c.Tag == "Signature" && c.NamespaceURI() == dsig.Namespace {
			if sig != nil {
				return nil, errors.New("more than one Signature")
			}
			sig = c
		}
	}
	if sig == nil {
		return nil, ErrUnsigned
	}
	si, err := only(sig, dsig.Namespace, "SignedInfo")
	if err != nil {
		return nil, err
	}
	cm, err := only(si, dsig.Namespace, "CanonicalizationMethod")
	if err != nil {
		return nil, err
	}
	siAlg := cm.SelectAttrValue("Algorithm", "")
	if !c14nAlgorithms[siAlg] {
		return nil, fmt.Errorf("SignedInfo canonicalisation %s is not canonical XML 1.0 or exclusive c14n", siAlg)
	}
	sm, err := only(si, dsig.Namespace, "SignatureMethod")
	if err != nil {
		return nil, err
	}
	method := sm.SelectAttrValue("Algorithm", "")
	if method != AlgRSASHA256 && method != AlgECDSASHA256 {
		return nil, fmt.Errorf("signature method %s is not RSA-SHA256 or ECDSA-SHA256", method)
	}

	// The signed object and the ReplayProtect property must both be
	// referenced, and the Ids must name exactly those elements.
	props, err := signatureProperty(sig)
	if err != nil {
		return nil, err
	}
	targets := map[string]*etree.Element{}
	if id := idOf(so); id != "" {
		targets["#"+id] = so
	}
	// The replay protection may be referenced by its SignatureProperty,
	// the SignatureProperties around it or the Object holding them (the
	// spec's Figure 23 references the Object).
	for el := props; el != nil && el != sig; el = el.Parent() {
		if id := idOf(el); id != "" {
			targets["#"+id] = el
		}
	}
	ids := map[string]int{}
	countIDs(root, ids)
	covered := map[*etree.Element]bool{}
	for _, ref := range si.ChildElements() {
		if ref.Tag != "Reference" || ref.NamespaceURI() != dsig.Namespace {
			continue
		}
		uri := ref.SelectAttrValue("URI", "")
		el := targets[uri]
		if el == nil {
			return nil, fmt.Errorf("reference %q is neither the signed object nor the replay protection", uri)
		}
		if ids[strings.TrimPrefix(uri, "#")] != 1 {
			return nil, fmt.Errorf("Id %q is not unique in the payload", uri)
		}
		refAlg, err := checkTransforms(ref)
		if err != nil {
			return nil, err
		}
		dm, err := only(ref, dsig.Namespace, "DigestMethod")
		if err != nil {
			return nil, err
		}
		if dm.SelectAttrValue("Algorithm", "") != AlgSHA256 {
			return nil, errors.New("digest method is not SHA-256")
		}
		dv, err := only(ref, dsig.Namespace, "DigestValue")
		if err != nil {
			return nil, err
		}
		want, err := base64.StdEncoding.DecodeString(strings.TrimSpace(dv.Text()))
		if err != nil {
			return nil, errors.New("digest value is not base64")
		}
		got, err := digestOf(el, refAlg)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, want) {
			return nil, fmt.Errorf("digest of %s does not match: the payload was changed", uri)
		}
		covered[el] = true
	}
	replayCovered := false
	for el := props; el != nil && el != sig; el = el.Parent() {
		replayCovered = replayCovered || covered[el]
	}
	if !covered[so] || !replayCovered {
		return nil, errors.New("the signature does not cover both the signed object and the replay protection")
	}

	cert, err := keyInfoCert(sig)
	if err != nil {
		return nil, err
	}
	svEl, err := only(sig, dsig.Namespace, "SignatureValue")
	if err != nil {
		return nil, err
	}
	sv, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(svEl.Text()), ""))
	if err != nil {
		return nil, errors.New("signature value is not base64")
	}
	c14n, err := canonical(si, siAlg)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(c14n)
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if method != AlgRSASHA256 || rsa.VerifyPKCS1v15(pk, crypto.SHA256, h[:], sv) != nil {
			return nil, errors.New("the signature value does not verify with the certificate in KeyInfo")
		}
	case *ecdsa.PublicKey:
		size := (pk.Curve.Params().BitSize + 7) / 8
		good := false
		if method == AlgECDSASHA256 {
			if len(sv) == 2*size {
				good = ecdsa.Verify(pk, h[:], new(big.Int).SetBytes(sv[:size]), new(big.Int).SetBytes(sv[size:]))
			} else {
				good = ecdsa.VerifyASN1(pk, h[:], sv) // some signers write DER
			}
		}
		if !good {
			return nil, errors.New("the signature value does not verify with the certificate in KeyInfo")
		}
	default:
		return nil, fmt.Errorf("certificate key type %T is not RSA or ECDSA", pk)
	}

	v := &Verified{Cert: cert}
	rp, err := only(props, NSDsp, "ReplayProtect")
	if err != nil {
		return nil, err
	}
	ts, err := only(rp, NSDsp, "timestamp")
	if err != nil {
		return nil, err
	}
	if v.Timestamp, err = ParseTime(ts.Text()); err != nil {
		return nil, fmt.Errorf("ReplayProtect timestamp: %w", err)
	}
	n, err := only(rp, NSDsp, "nonce")
	if err != nil {
		return nil, err
	}
	if v.Nonce = strings.TrimSpace(n.Text()); v.Nonce == "" {
		return nil, errors.New("ReplayProtect nonce is empty")
	}
	return v, nil
}

// signatureProperty finds Object/SignatureProperties/SignatureProperty
// holding ReplayProtect inside the signature.
func signatureProperty(sig *etree.Element) (*etree.Element, error) {
	var found *etree.Element
	for _, obj := range sig.ChildElements() {
		if obj.Tag != "Object" || obj.NamespaceURI() != dsig.Namespace {
			continue
		}
		for _, sps := range obj.ChildElements() {
			if sps.Tag != "SignatureProperties" || sps.NamespaceURI() != dsig.Namespace {
				continue
			}
			for _, sp := range sps.ChildElements() {
				if sp.Tag == "SignatureProperty" && sp.NamespaceURI() == dsig.Namespace && childNS(sp, NSDsp, "ReplayProtect") != nil {
					if found != nil {
						return nil, errors.New("more than one ReplayProtect")
					}
					found = sp
				}
			}
		}
	}
	if found == nil {
		return nil, errors.New("the signature carries no ReplayProtect property")
	}
	return found, nil
}

func countIDs(el *etree.Element, ids map[string]int) {
	if id := idOf(el); id != "" {
		ids[id]++
	}
	for _, c := range el.ChildElements() {
		countIDs(c, ids)
	}
}

// checkTransforms accepts at most one transform, a canonicalisation, and
// returns it; without one a same-document reference is canonical XML 1.0.
func checkTransforms(ref *etree.Element) (string, error) {
	tr := childNS(ref, dsig.Namespace, "Transforms")
	if tr == nil {
		return AlgC14N, nil
	}
	alg, n := AlgC14N, 0
	for _, t := range tr.ChildElements() {
		alg = t.SelectAttrValue("Algorithm", "")
		if !c14nAlgorithms[alg] {
			return "", fmt.Errorf("transform %s is not a canonicalisation", alg)
		}
		n++
	}
	if n > 1 {
		return "", errors.New("a reference has more than one transform")
	}
	return alg, nil
}

func keyInfoCert(sig *etree.Element) (*x509.Certificate, error) {
	ki, err := only(sig, dsig.Namespace, "KeyInfo")
	if err != nil {
		return nil, err
	}
	xd, err := only(ki, dsig.Namespace, "X509Data")
	if err != nil {
		return nil, err
	}
	xc := childNS(xd, dsig.Namespace, "X509Certificate")
	if xc == nil {
		return nil, errors.New("KeyInfo carries no X509Certificate")
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Text()), ""))
	if err != nil {
		return nil, errors.New("X509Certificate is not base64")
	}
	return x509.ParseCertificate(der)
}

// ReplayGuard refuses signatures outside a time window around now and
// nonces already seen from the same signer within it. Nonces are kept for
// twice the window, in memory and, when Store is set, in the
// application's durable key-value store, so a replay after a restart or a
// change of leader is still caught.
type ReplayGuard struct {
	Window time.Duration
	Now    func() time.Time
	// Store, when set, keeps every accepted nonce durably.
	Store NonceStore

	mu   sync.Mutex
	seen map[string]time.Time // fingerprint|nonce → forget after
}

// NonceStore keeps nonces across restarts (a durable key-value store).
type NonceStore interface {
	Load(ctx context.Context) (map[string]json.RawMessage, error)
	Put(ctx context.Context, k string, v any) error
	Delete(ctx context.Context, k string) error
}

// NonceState is a suggested name for the key-value map holding seen
// nonces.
const NonceState = "openadr-nonces"

// Restore loads the stored nonces that have not expired and drops the
// rest from the store.
func (g *ReplayGuard) Restore(ctx context.Context) (int, error) {
	if g.Store == nil {
		return 0, nil
	}
	all, err := g.Store.Load(ctx)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	if g.Now != nil {
		now = g.Now()
	}
	g.mu.Lock()
	if g.seen == nil {
		g.seen = map[string]time.Time{}
	}
	var stale []string
	for k, raw := range all {
		var until time.Time
		if json.Unmarshal(raw, &until) != nil || !now.Before(until) {
			stale = append(stale, k)
			continue
		}
		g.seen[k] = until
	}
	n := len(g.seen)
	g.mu.Unlock()
	for _, k := range stale {
		_ = g.Store.Delete(ctx, k)
	}
	return n, nil
}

// maxNonces bounds the guard's memory; beyond it new signatures are
// refused until old nonces expire.
const maxNonces = 1 << 17

// Check accepts v once.
func (g *ReplayGuard) Check(v *Verified) error {
	now := time.Now()
	if g.Now != nil {
		now = g.Now()
	}
	w := g.Window
	if w <= 0 {
		w = 5 * time.Minute
	}
	if d := now.Sub(v.Timestamp); d > w || d < -w {
		return fmt.Errorf("the ReplayProtect timestamp %s is outside ±%s of now", FormatTime(v.Timestamp), w)
	}
	key := Fingerprint(v.Cert.Raw) + "|" + v.Nonce
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen == nil {
		g.seen = map[string]time.Time{}
	}
	if until, ok := g.seen[key]; ok && now.Before(until) {
		return errors.New("the ReplayProtect nonce was already used: a replayed message")
	}
	var expired []string
	if len(g.seen) >= maxNonces/2 || (g.Store != nil && len(g.seen)%256 == 0) {
		for k, until := range g.seen {
			if !now.Before(until) {
				delete(g.seen, k)
				expired = append(expired, k)
			}
		}
		if len(g.seen) >= maxNonces {
			return errors.New("too many recent signed messages to track their nonces")
		}
	}
	until := now.Add(2 * w)
	g.seen[key] = until
	if g.Store != nil {
		// Stored before the message is acted on; a store failure only
		// loses the durability of this nonce.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = g.Store.Put(ctx, key, until)
		for _, k := range expired {
			_ = g.Store.Delete(ctx, k)
		}
		cancel()
	}
	return nil
}
