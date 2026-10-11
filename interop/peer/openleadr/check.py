# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# Reads OpenADR 2.0b payloads with OpenLEADR's own code: its schema check
# (the 2.0b XSDs it ships), its XML signature check (signxml, with the
# ReplayProtect rules) and its parser. Commands on standard input:
#
#   check <file> [<fingerprint>]   schema and parser; with a fingerprint
#                                  also the signature, which must be made
#                                  by that certificate
#   quit
#
# Answers "PEER ok <file> <message type>" or "PEER fail <file> <error>".

import sys

from openleadr.messaging import parse_message, validate_xml_schema, validate_xml_signature

print("PEER ready", flush=True)
for line in sys.stdin:
    parts = line.split()
    if not parts or parts[0] == "quit":
        break
    name = parts[1]
    try:
        with open(name, "rb") as f:
            content = f.read()
        tree = validate_xml_schema(content)
        if len(parts) > 2:
            validate_xml_signature(tree, cert_fingerprint=parts[2])
        message_type, payload = parse_message(content)
        print("PEER ok", name, message_type, flush=True)
    except Exception as err:
        print("PEER fail", name, f"{type(err).__name__}: {err}".replace("\n", " "), flush=True)
