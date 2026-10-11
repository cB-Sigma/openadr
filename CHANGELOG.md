# Changelog

All notable changes to this module. Versions follow semantic versioning;
before v1 the API may change in minor versions.

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
