# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# An OpenLEADR VEN client for the tests of this module's VTN (oadr2b/vtn).
# It registers, offers a TELEMETRY_USAGE report of one voltage reading,
# opts in to every event, polls, and prints what happens as "PEER ..."
# lines.
#
#   python olr_ven.py <vtn-url> [<cert-dir> <vtn-fingerprint>]
#
# With a certificate directory (ca.pem, ven.crt, ven.key) it uses a TLS
# client certificate, signs its messages and checks the VTN's signatures
# against <vtn-fingerprint>.
#
# Commands on standard input: "cancel" (cancel the registration),
# "opt <event-id> <modification-number> <optIn|optOut>", "cancelopt <opt-id>",
# "state" (print venID, registrationID and report requests), "quit".

import asyncio
import logging
import sys
from datetime import timedelta

from openleadr import OpenADRClient, enable_default_logging

enable_default_logging(level=logging.WARNING)


def say(*parts):
    print("PEER", *parts, flush=True)


vtn_url = sys.argv[1]
cert_dir = sys.argv[2] if len(sys.argv) > 2 else None
vtn_fp = sys.argv[3] if len(sys.argv) > 3 else None


async def on_event(event):
    d = event["event_descriptor"]
    sig = event["event_signals"][0]
    say("event", d["event_id"], d["modification_number"], d["event_status"], sig["signal_name"],
        sig["intervals"][0]["signal_payload"])
    return "optIn"


def read_voltage():
    return 231.5


async def after_parse(message_type, payload):
    say("received", message_type)


async def main():
    kw = {}
    if cert_dir:
        kw = dict(cert=f"{cert_dir}/ven.crt", key=f"{cert_dir}/ven.key", ca_file=f"{cert_dir}/ca.pem",
                  vtn_fingerprint=vtn_fp, show_fingerprint=False)
    client = OpenADRClient(ven_name="olr-ven", vtn_url=vtn_url, **kw)
    client.add_handler("on_event", on_event)
    client.add_handler("on_update_event", on_event)
    client.add_hook("after_parse_xml", after_parse)
    client.add_report(callback=read_voltage, resource_id="device-1", measurement="voltage",
                      report_specifier_id="olr-usage", r_id="olr-voltage",
                      sampling_rate=timedelta(seconds=1), report_duration=timedelta(hours=1))
    await client.run()
    say("registered", client.ven_id, client.registration_id)
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        cmd = line.strip()
        if not line or cmd == "quit":
            break
        parts = cmd.split()
        if cmd == "cancel":
            await client.cancel_party_registration()
            say("canceled", client.registration_id)
        elif parts and parts[0] == "opt":
            opt_id = await client.create_opt(parts[3], "participating", [{"ven_id": client.ven_id}],
                                             event_id=parts[1], modification_number=int(parts[2]))
            say("opt-created", opt_id)
        elif parts and parts[0] == "cancelopt":
            res = await client.cancel_opt(parts[1])
            say("opt-cancelled", parts[1], res)
        elif cmd == "state":
            say("state", client.ven_id, client.registration_id,
                ",".join(sorted(r["report_request_id"] for r in client.report_requests or [])) or "-")
    await client.stop()


asyncio.run(main())
