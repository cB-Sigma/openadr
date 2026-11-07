# Changelog

All notable changes to this module. Versions follow semantic versioning;
before v1 the API may change in minor versions.

## v0.2.1 (2026-11-07)

- Fix: `oadr3/vtn` gave a VEN 404 for a program or event targeted at it
  when the VEN read it by ID (`GET /programs/{id}`, `GET /events/{id}`)
  without a `targets` query parameter, which the 3.0.1 and 3.1.0
  definitions do not give those operations. A VEN now sees such an object
  when it carries a target business logic granted the VEN (through its
  ven or resources), with those targets shown; an object targeted
  elsewhere is still not found, and searches still filter by the targets
  named. Reported by @boeboe (#1).

## v0.2.0 (2026-10-11)

Additions only; the v0.1.0 API is unchanged.

- New: `oadr2b/vtn`, a ready OpenADR 2.0b VTN as an `http.Handler`:
  registration, poll and push, events (modification, cancellation,
  opt-in/opt-out), opts, reports, signatures, the TLS profile with the
  client certificate as identity, business logic in callbacks, a
  pluggable registration `Store` (`EventSpec`, `RequestAll`,
  `ServerTLSConfig`, `Serve`).
- New: `oadr2b/ven`, a ready OpenADR 2.0b VEN (`New`, `Run`, `OnEvent`,
  `ReadData`, opts, a push listener).
- Interop: OpenLEADR 0.5.36's VEN client against `oadr2b/vtn` and its
  VTN against `oadr2b/ven`, over HTTP and mutual TLS with signatures.

- New: `oadr3/vtn`, an OpenADR 3 VTN as an `http.Handler`: the 3.1 REST
  API (3.0 with `Config.Version`) for programs, events, reports,
  subscriptions, vens and resources; the OAuth2 client-credentials token
  endpoint and `GET /auth/server`; business-logic and VEN scopes and
  external tokens through an `Authenticator`; object privacy between
  VENs; filters and paging; problem answers; a pluggable `Store` with
  `MemoryStore`; business logic in process (`Create`, `Update`,
  `Delete`, `Get`, `List`, `OnChange`); an optional OpenAPI `Validator`
  on every request and answer.
- New: webhook delivery in `oadr3/vtn`: callback echo check, bearer
  token, ordered delivery per callback, retries with back-off, broken
  callbacks skipped until their subscription is written again, private
  addresses and redirects refused by default, `NotificationIDHeader`,
  and an optional HMAC-SHA256 `SignatureHeader` (`Sign`,
  `VerifySignature`).
- New: the MQTT notifier of OpenADR 3.1 in `oadr3/vtn`, publishing
  through a `Publisher` you supply, with `GET /notifiers`, the topic
  listings and the broker rules `MQTTLogin` and `MQTTAllowed`.
- Interop: openleadr-rs v0.2.6's client integration tests against
  `oadr3/vtn` (16 of 17 pass; the 17th checks a refusal the definition
  does not ask for), and OpenAPI checks of both ends against the
  OpenADR 3.1.0 and 3.0.1 definitions, fetched at test time.

## v0.1.0 (2026-10-11)

First release as a module of its own, split from SigmaM2M: OpenADR 2.0b
and 2.0a messages and codec, XML signatures with a replay guard, simple
HTTP and XMPP, the TLS rules, schema validation with user-supplied XSDs
(`oadr2b`, `oadr2b/xmpp`); OpenADR 3 objects, checks, event timing and
REST client (`oadr3`); local VTN discovery (`oadr3/mdns`).

- Fixed: `Marshal` writes oadrSignedObject's Id as oadr:Id, as the 2.0b
  schema requires; it wrote it unqualified, which OpenLEADR's schema
  check refused when a message read with an Id was written back.
  `Unmarshal` still reads both forms.
- The simulators and their command live in their own module,
  [openadr-sim](https://github.com/cB-Sigma/openadr-sim), with the tests
  that drive them.
- Interop tests against OpenLEADR 0.5.36 and openleadr-rs v0.2.6 in a
  nested test-only module, `interop`.
