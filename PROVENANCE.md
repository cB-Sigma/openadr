# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go from the specifications
below. No code was ported or copied from another OpenADR, XMPP or mDNS
implementation (the OpenADR Alliance's reference implementations,
OpenLEADR, openleadr-rs, EPRI's VTN and VEN and others were not used as
sources). The code came with SigmaM2M's first commit (2026-09-27), as
part of its OpenADR 2.0b and OpenADR 3 integrations, and was moved into
this module on 2026-10-06 with `git mv`:

| Here | From SigmaM2M's |
|---|---|
| `oadr2b`: codec.go, payload.go, payload_a.go, schema.go, transport.go, xmlsig.go (signer, verifier, replay guard), payload_test.go, schema_test.go | OpenADR 2.0b integration, the same files |
| `oadr2b/tls.go` | the TLS profiles, mandated suites and key-size checks, and the PEM loaders of that integration |
| `oadr2b/names.go` | its response codes, profile, service and transport names |
| `oadr2b/xmlsig_internal_test.go` | its signature layout test |
| `oadr2b/xmpp` | its XMPP package (SCRAM now from github.com/cB-Sigma/iotcrypto) |
| `oadr3`: client.go, objects.go (object model, checks, event timing) | OpenADR 3 integration, the same files; the object store stayed |
| `oadr3/mdns` | its local-discovery package; on 2026-10-06 the responder and browser moved to github.com/cB-Sigma/mdns and this package kept `ServiceType`, `VTNRecords` and a renaming `Announce` |

Changes that came with the move: helpers the integrations call were
exported (`LoadSchemas`, `SchemaSet.Check`, `PostXML`, `ReadRequest`,
`WriteXML`, `ApplyTLSProfile`, `LoadCertificates`, `Signer.Certificate`,
`Str`, `CheckRequest`, `EventWindow`, `Problem` and others); the API
client takes an `oadr3.Validator` interface instead of SigmaM2M's
OpenAPI validator. The `Example` tests are new.

History:

- 2026-10-06: moved into this module, with the simulators.
- 2026-10-11: the simulators, their command and the tests that drive
  them moved to the openadr-sim module (with `git mv`), so the library
  does not depend on its simulators. The module path became
  github.com/cB-Sigma/openadr. Comments that named SigmaM2M's internal
  files or findings were reworded. The interop module was added and run
  against OpenLEADR 0.5.36 and openleadr-rs v0.2.6; one bug was found
  and fixed (`Marshal` wrote oadrSignedObject's Id unqualified;
  `TestMarshalQualifiesSignedObjectID`).
- 2026-10-11 (v0.2.0): `oadr3/vtn` added, ported from SigmaM2M's own
  OpenADR 3 VTN (the same author's code; table below) with SigmaM2M's parts cut away (its key-value store, oneM2M
  records, licence, JWKS client, embedded MQTT broker) behind `Store`,
  `OnChange`, `Authenticator` and `Publisher`. Written new for the
  library: the `Store` interface and `MemoryStore`, OpenADR 3.0 mode
  (v30.go), webhook delivery in order per callback, the notification ID
  and signature headers, `EventOrder`, IDs that sort by creation, and
  the in-process business-logic methods. The interop module gained
  openleadr-rs's client test suite and OpenAPI checks against the
  OpenADR 3 definitions; they led to two changes (a BL resource without
  clientID takes its ven's; `EventOrder`).

| `oadr3/vtn` file | From SigmaM2M's OpenADR 3 VTN |
|---|---|
| vtn.go | openadr3.go (client checks, base URL, IDs), api.go (routes, answers, problems, bodies, handlers) |
| auth.go | auth.go (scopes, HS256 tokens, the token endpoint) |
| objects.go | api.go (queries, filters, privacy and grants), store.go (writes, rules, deletes, fan-out of notifications) |
| webhook.go | notify.go (delivery, retries, broken callbacks), store.go (the echo check), openadr3.go (the dialler refusing private addresses) |
| mqtt.go | notify.go (topics, login and subscribe rules, `/notifiers` and the topic listings) |
| store.go | store.go (the order objects are listed in) |
| v30.go, the tests, the example | new |

The same day `oadr2b/vtn` and `oadr2b/ven` were added, ported from
SigmaM2M's own OpenADR 2.0b VTN and VEN (the same author's code) and from openadr-sim, with SigmaM2M's data and
oneM2M parts replaced by callbacks and a `Store`:

| File | From |
|---|---|
| oadr2b/vtn/vtn.go | SigmaM2M's vtn.go (VEN identity, dispatch, registration, poll) |
| oadr2b/vtn/events.go | events.go (event status, what may be sent, ranking, acknowledgements, opts) |
| oadr2b/vtn/reports.go | reports_vtn.go; `RequestAll` from openadr-sim's vtnsim |
| oadr2b/vtn/push.go | push.go |
| oadr2b/vtn/store.go, serve.go | new |
| oadr2b/ven/ven.go | ven.go (registration, polling, handling the VTN's messages, events, back-off) and ven_transport.go (push) |
| oadr2b/ven/reports.go | reports_ven.go |
| internal/testpki | openadr-sim's internal/testpki, made safe for concurrent use |
| the tests, the examples, interop/oadr2b_vtnven_test.go and peer/openleadr/olr_ven.py, olr_vtn.py | new |

## Sources

| Area | Followed |
|---|---|
| 2.0b messages, codes, simple HTTP, XML signatures, TLS (oadr2b) | OpenADR 2.0b Profile Specification v1.1 (updated 2015-11-17) and its conformance rules; schema Profile_B_Schema_20130701 read as reference |
| 2.0a messages (payload_a.go) | OpenADR 2.0a Profile Specification v1.0; schema oadr20a_schema read as reference |
| XML signatures (xmlsig.go) | W3C XML Signature Syntax and Processing, Canonical XML 1.0, Exclusive XML Canonicalization 1.0 |
| XMPP (oadr2b/xmpp) | RFC 6120, RFC 6121, XEP-0030, XEP-0199; SASL per RFC 4422 (EXTERNAL), RFC 4616 (PLAIN) and RFC 5802 / RFC 7677 (SCRAM) |
| OpenADR 3 objects and client (oadr3) | OpenADR 3.1.0 (2025-08-01): the OpenAPI definition and the Definition and User Guide documents, read as reference |
| OpenADR 3 VTN (oadr3/vtn) | the same, and the OpenADR 3.0.1 OpenAPI definition for 3.0 mode; RFC 6749 section 4.4 and RFC 7519 for tokens; RFC 2104 for the HMAC signature (our extension) |
| Local VTN discovery (oadr3/mdns) | the OpenADR 3.1.0 Definition's local discovery; RFC 6762 (multicast DNS), RFC 6763 (DNS-SD) |
| Interop tests (interop/) | our own tests and scripts (peer/openleadr/check.py, make.py) calling OpenLEADR 0.5.36's create_message, schema check, signature check and parser, and driving openleadr-rs v0.2.6's REST API; both are installed or built at test time |

The OpenADR Alliance documents and schemas are copyright the OpenADR
Alliance and are not redistributed: none of their text or schema content
is in this module. Element names, namespaces, codes, paths and rules are
used as facts with section and rule references, in our own words.

## Not here

Since v0.2.0 the module has ready 2.0b VTN and VEN and an OpenADR 3
VTN, ported from SigmaM2M's. SigmaM2M keeps its own copies for now
(they read and write SigmaM2M's data, and XMPP delivery, 2.0a and the
oneM2M mapping stay there); moving SigmaM2M onto these packages is
left for a later release. Not here: XMPP and 2.0a in the ready VTN and
VEN, an embedded MQTT broker (the OpenADR 3 VTN publishes through one
you supply), and an OpenADR 3 VEN state machine (the `APIClient` and
openadr-sim's VEN cover the exchanges).

## Notes for reviewers

No passage is known to be copied. Doc comments cite sections and
conformance rule numbers in our own words.

## Test vectors and where they come from

| Test | Source |
|---|---|
| oadr2b/payload_test.go, interop_regress_test.go | messages written by hand for these tests from the element names and namespaces |
| oadr2b/xmlsig_internal_test.go | the signature layout the 2.0b profile shows, rebuilt in our own words with generated keys |
| oadr2b/schema_test.go | needs the user's copy of the Alliance XSDs (skipped without it) |
| oadr2b/xmpp, oadr3, oadr3/mdns, oadr3/vtn | our own values; keys and certificates generated when the tests run |
| interop/ | OpenLEADR 0.5.36 and openleadr-rs v0.2.6 (its VTN, and its client library's own integration tests), at test time; the OpenADR 3.1.0 and 3.0.1 OpenAPI definitions, fetched at test time |

All IDs, URLs and names are made-up demo values.
