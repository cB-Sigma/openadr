# openadr

OpenADR 2.0b (and 2.0a) and OpenADR 3 in pure Go: messages, XML signatures, transports and clients; not affiliated with the OpenADR Alliance.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/openadr.svg)](https://pkg.go.dev/github.com/cB-Sigma/openadr) [![test](https://github.com/cB-Sigma/openadr/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/openadr/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

For OpenADR 2.0b it has the whole message model with a codec that
writes the prefixed form other implementations expect, XML signatures
with replay protection, the simple-HTTP and XMPP transports, the TLS
rules, and schema validation against XSDs you supply. For OpenADR 3 it
has the object model, request checks, event timing, a REST client with
OAuth2 client credentials, and local VTN discovery over mDNS/DNS-SD.
No cgo. It was written for SigmaM2M, a oneM2M platform, whose OpenADR
VTN and VEN are built on it; those state machines are not part of this
module. Simulated VENs and VTNs of both versions are in
[openadr-sim](https://github.com/cB-Sigma/openadr-sim).

## Features

| Feature | Status |
|---|---|
| 2.0b messages: registration, events, opts, reports, poll (`oadr2b.SignedObject`, `Marshal`, `Unmarshal`) | decode and encode, with the conventional prefixes |
| 2.0a messages (`MessageA`, `MarshalA`, `UnmarshalA`), mapping from 2.0b events (`ToA`) | decode and encode |
| XML signatures (`Signer`, `VerifyPayload`) | sign: canonical XML 1.0, SHA-256, RSA or ECDSA; verify: canonical XML 1.0 or exclusive canonicalisation, ECDSA raw or DER |
| Replay protection (`ReplayGuard`) | time window and nonces per signer, with a hook for a durable nonce store (`NonceStore`) |
| Simple HTTP (`PostXML`, `ReadRequest`, `WriteXML`) | client and server helpers, gzip and deflate |
| XMPP (`oadr2b/xmpp`) | client and server: STARTTLS, SASL EXTERNAL, PLAIN, SCRAM-SHA-1 and SCRAM-SHA-256, resource binding, IQ and message stanzas, service discovery, ping |
| TLS rules (`ApplyTLSProfile`, `MandatedCipherSuites`, `CheckKeySize`, `LoadCertificates`) | the two mandated suites over TLS 1.2, or a compatible profile; minimum key sizes |
| Certificate fingerprints (`Fingerprint`, `NormalizeFingerprint`) | yes |
| Schema validation (`LoadSchemas`, `SchemaSet.Check`) | yes, with XSDs you supply (not shipped, see Licence) |
| OpenADR 3 objects and checks (`oadr3.Object`, `CheckRequest`, `Problem`) | all six object types |
| OpenADR 3 event timing (`EventWindow`, `Transpired`, `CurrentInterval`) | yes |
| OpenADR 3 client (`oadr3.APIClient`) | token endpoint discovery, client-credentials grant, one retry with a new token after 401, paging, an optional OpenAPI `Validator` |
| Local VTN discovery (`oadr3/mdns`) | announce with renaming after a conflict, browse; over [mdns](https://github.com/cB-Sigma/mdns) |
| A ready VTN or VEN | no: this module has the protocol parts; the simulators in openadr-sim are simple complete ones |
| OpenADR 3 VTN server | no |

## Choosing a Go OpenADR library

No other Go OpenADR implementation turned up in a GitHub search on
2026-10-11, so the comparison is with the open-source implementations
in other languages, read from their source at the versions named on
2026-10-11. Check the projects themselves before relying on a row.

| | this module | OpenLEADR (openleadr-python) 0.5.36 | openleadr-rs v0.2.6 (b20d616) | EPRI OpenADR VEN library (16546464, 2016-08-30) | EPRI OpenADR VTN (acda0ba, 2019-12-09) |
|---|---|---|---|---|---|
| Language | Go | Python | Rust | C++ | Ruby on Rails |
| OpenADR versions | 2.0a, 2.0b, 3.1 | 2.0b | 3.1 (3.0 before v0.2) | 2.0b | 2.0a, 2.0b |
| Roles | building blocks for both; simulated VEN and VTN in openadr-sim | VTN server and VEN client | VTN server and VEN client library | VEN | VTN with a web interface |
| 2.0b simple HTTP | pull and push helpers | pull (its client registers for pull) | n/a | pull only (its README) | yes |
| 2.0b XMPP | client and server | no | n/a | no | no transport found in its source |
| XML signatures | sign and verify, RSA and ECDSA, replay guard with durable store hook | sign and verify (signxml), replay window 5 s, in memory | n/a | no signing code found | registration flag only; no signing code found |
| Schema validation | with XSDs you supply | every message received, with the XSDs it ships | n/a | code generated from the XSDs it ships | no |
| OpenADR 3 client | yes, OAuth2, paging | no | yes | n/a | n/a |
| OpenADR 3 VTN | no | n/a | yes (PostgreSQL; subscriptions by webhook not supported, per its README) | n/a | n/a |
| Local VTN discovery (mDNS) | yes | n/a | yes (feature `mdns`) | n/a | n/a |
| Interop evidence | against OpenLEADR and openleadr-rs (below) | its own tests | OpenADR Alliance test suite results in its README | its own tests | its own tests |
| Maintained | yes | yes (release 2026-09-03) | yes | no commits since 2016 | support discontinued (its README) |
| Licence | Apache-2.0 | Apache-2.0 | Apache-2.0 or MIT | BSD-3-Clause | BSD-3-Clause |

Pick this module for OpenADR in Go, for 2.0a or XMPP, or when you need
the protocol parts under your own VTN or VEN. Pick OpenLEADR for a
ready 2.0b VTN or VEN in Python with the least code of your own. Pick
openleadr-rs for a ready OpenADR 3 VTN, or a Rust VEN. The EPRI projects
are useful as references but are no longer maintained.

## Install

```
go get github.com/cB-Sigma/openadr@latest
```

Requires Go 1.27.1 or later.

## Quick start

```go
import (
	"github.com/cB-Sigma/openadr/oadr2b"
	"github.com/cB-Sigma/openadr/oadr3"
)

// 2.0b: write, sign and post a poll; read and check the answer.
s, _ := oadr2b.NewSigner(cert) // a tls.Certificate with an RSA or ECDSA key
b, _ := oadr2b.Marshal(oadr2b.SignedObject{Poll: &oadr2b.Poll{VenID: "ven-1"}})
b, _ = s.Sign(b)
ans, state, _ := oadr2b.PostXML(ctx, httpClient, vtnURL+oadr2b.PathBase+oadr2b.ServicePoll, b)
v, _ := oadr2b.VerifyPayload(ans) // and check oadr2b.Fingerprint(v.Cert.Raw)
_ = guard.Check(v)                // an oadr2b.ReplayGuard
so, _ := oadr2b.Unmarshal(ans)
fmt.Println(oadr2b.MessageName(so), state.CipherSuite)

// OpenADR 3: list the events a VEN can see.
c := oadr3.NewClient(oadr3.ClientConfig{BaseURL: "https://vtn.example/openadr3/3.1.0", ClientID: id, Secret: secret})
events, _ := c.All(ctx, "/events", nil)
for _, ev := range events {
	w := oadr3.EventWindow(ev)
	fmt.Println(oadr3.Str(ev, "id"), w.Start, w.End)
}
```

The runnable versions are the `Example` tests of `oadr2b` and `oadr3`.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/openadr

| Package | What it does |
|---|---|
| `oadr2b` | 2.0b and 2.0a payloads (`SignedObject`, `MessageA`, every message of both profiles), `Marshal`/`Unmarshal`, ISO 8601 durations and times, fingerprints, response codes and service paths; XML signatures (`Signer`, `VerifyPayload`, `ReplayGuard`, `NonceStore`); simple-HTTP helpers; TLS profiles and key sizes; `LoadSchemas` |
| `oadr2b/xmpp` | the XMPP subset the 2.0 profiles use: `Server` and `Client` |
| `oadr3` | OpenADR 3 objects (`Object`, the object types), request checks (`CheckRequest`, `Problem`), event timing (`EventWindow`, `Transpired`, `CurrentInterval`), `APIClient` |
| `oadr3/mdns` | local VTN discovery: `ServiceType`, `VTNRecords`, `Announce` (renames the instance after a conflict), `Browse` |
| `interop` (nested module, tests only) | this library against OpenLEADR and openleadr-rs, in containers |

Changes per version are in [CHANGELOG.md](CHANGELOG.md).

## Testing

```
go test -race ./...
cd interop && SIGMA_OPENADR_INTEROP=1 go test -v ./...   # needs Docker
```

The schema tests in `oadr2b` that need the OpenADR Alliance XSDs run
when `SIGMA_TEST_OPENADR_XSD_DIR` names a folder holding them and are
skipped otherwise. Tests carry `// Covers: SIG-...` comments:
requirement IDs of the SigmaM2M project's compliance report, with no
meaning outside it. The tests that drive the simulators are in
openadr-sim, so this module does not depend on its simulators.

`interop/` is a nested module with its own go.mod. Its tests build two
images: `interop/peer/openleadr` (python:3.12.10-slim with openleadr
0.5.36 from PyPI) and `interop/peer/openleadr-rs` (openleadr-rs cloned
at tag v0.2.6, commit b20d616, built with rust:1.94-alpine, run on
alpine:3.20 next to postgres:16). They are skipped unless
`SIGMA_OPENADR_INTEROP=1` is set and Docker answers.

### Interop tested against

Run on 2026-10-11 in Docker Desktop 29.4.3 on arm64.

- OpenLEADR 0.5.36: all 23 2.0b message types as this library writes
  them pass OpenLEADR's schema check (with the 2.0b XSDs it ships) and
  its parser, and the same messages signed by this library with ECDSA
  P-256 and RSA 2048 pass its signature check (signxml, with
  ReplayProtect and the signer's fingerprint). The same 23 types written
  by OpenLEADR (signed with ECDSA) are read by `Unmarshal` as the same
  type, pass `VerifyPayload` and `ReplayGuard`, pass `LoadSchemas`
  with OpenLEADR's copy of the XSDs (copied out of the image at test
  time), and, written back by `Marshal`, pass OpenLEADR's checks again.
  The last step found one bug, fixed in v0.1.0: `Marshal` wrote the Id
  of oadrSignedObject unqualified, which the schema does not allow.
  It also showed OpenLEADR writing powerAttributes inside a
  power:voltage item, which the 2.0b schema does not allow and
  `LoadSchemas` refuses.
- openleadr-rs v0.2.6 (OpenADR 3.1 VTN on PostgreSQL 16, its own user
  fixtures): `APIClient` discovered the token endpoint, got tokens with
  client credentials, created 53 programs and an event, paged through
  all 53 programs, read the event's window with `EventWindow`, and got
  the VTN's 404 and 403 answers as `HTTPError`; a wrong secret got no
  token.
- The simulators against OpenLEADR's VTN and VEN client and against
  openleadr-rs, over plain HTTP and mutual TLS with signatures: see
  [openadr-sim](https://github.com/cB-Sigma/openadr-sim).
- Not yet: XMPP against another implementation, 2.0a against another
  implementation, an OpenADR Alliance test harness or a certified VTN
  or VEN, OpenADR 3 webhooks against another VTN (openleadr-rs does not
  have them), and mDNS discovery against openleadr-rs's announcer.

## Related repositories

- [openadr-sim](https://github.com/cB-Sigma/openadr-sim): simulated
  OpenADR 2.0b and 2.0a VENs, a 2.0b VTN and OpenADR 3 VEN and webhook
  simulators, as Go packages and a command.
- [mdns](https://github.com/cB-Sigma/mdns), [xsd](https://github.com/cB-Sigma/xsd)
  and [iotcrypto](https://github.com/cB-Sigma/iotcrypto): the mDNS,
  XML Schema and SCRAM code this module uses.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.

"OpenADR" is a trademark of the OpenADR Alliance. This module is not
made, affiliated with, endorsed or certified by the OpenADR Alliance;
the name is used only to say which protocol it implements. No OpenADR
Alliance schema, OpenAPI definition or specification text is included:
the XSDs and the OpenAPI YAML are the Alliance's and not
redistributable, so `LoadSchemas` and the `Validator` take a copy you
supply.
