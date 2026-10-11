# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# Writes OpenADR 2.0b payloads made by OpenLEADR's create_message, signed
# with the given certificate and key, one file per message type
# (<out>/<type>.xml), and copies the schema files OpenLEADR ships to
# <out>/schema for the reader's own schema check. The message contents
# are our own demo values.
#
#   python make.py <out> <cert> <key>

import os
import shutil
import sys
from datetime import datetime, timedelta, timezone

import openleadr
from openleadr import objects
from openleadr.messaging import create_message

out, cert_path, key_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(cert_path, "rb") as f:
    cert = f.read()
with open(key_path, "rb") as f:
    key = f.read()

now = datetime.now(timezone.utc).replace(microsecond=0)
ok = {"response_code": 200, "response_description": "OK", "request_id": "req-1"}
profiles = [{"profile_name": "2.0b", "transports": [{"transport_name": "simpleHttp"}]}]

event = objects.Event(
    event_descriptor=objects.EventDescriptor(event_id="ev-1", modification_number=2,
                                             market_context="http://openleadr.test/mc",
                                             event_status="active", created_date_time=now, priority=1),
    active_period=objects.ActivePeriod(dtstart=now, duration=timedelta(hours=1)),
    event_signals=[objects.EventSignal(signal_name="simple", signal_type="level", signal_id="sig-1",
                                       intervals=[objects.Interval(dtstart=now, duration=timedelta(minutes=30),
                                                                   signal_payload=1.0),
                                                  objects.Interval(dtstart=now + timedelta(minutes=30),
                                                                   duration=timedelta(minutes=30),
                                                                   signal_payload=2.0)])],
    targets=[objects.Target(ven_id="ven-1")],
    response_required="always")

report = objects.Report(
    report_specifier_id="spec-1", report_name="METADATA_TELEMETRY_USAGE", created_date_time=now,
    duration=timedelta(hours=1), dtstart=now,
    report_descriptions=[objects.ReportDescription(
        r_id="rid-1", reading_type="Direct Read", report_type="reading", market_context="http://openleadr.test/mc",
        report_subject=objects.Target(resource_id="device-1"),
        report_data_source=objects.Target(resource_id="device-1"),
        sampling_rate=objects.SamplingRate(min_period=timedelta(seconds=10), max_period=timedelta(minutes=5), on_change=False),
        # powerReal: OpenLEADR 0.5.36 also writes powerAttributes inside
        # power:voltage, which the 2.0b schema does not allow.
        measurement=objects.Measurement(name="powerReal", description="RealPower", unit="W", scale="none",
                                        power_attributes=objects.PowerAttributes(hertz=50, voltage=230, ac=True)))])

data_report = objects.Report(
    report_specifier_id="spec-1", report_name="TELEMETRY_USAGE", created_date_time=now,
    report_request_id="rr-1", dtstart=now, duration=timedelta(minutes=1),
    intervals=[objects.ReportInterval(dtstart=now, duration=timedelta(minutes=1),
                                      report_payload=objects.ReportPayload(r_id="rid-1", value=231.5))])

request = objects.ReportRequest(
    report_request_id="rr-1",
    report_specifier=objects.ReportSpecifier(report_specifier_id="spec-1", granularity=timedelta(seconds=10),
                                             report_back_duration=timedelta(seconds=10),
                                             specifier_payloads=[objects.SpecifierPayload(r_id="rid-1", reading_type="Direct Read")]))

messages = {
    "oadrQueryRegistration": dict(request_id="req-1"),
    "oadrCreatePartyRegistration": dict(request_id="req-1", ven_id="ven-1", ven_name="olr-ven", profile_name="2.0b",
                                        transport_name="simpleHttp", transport_address=None, report_only=False,
                                        xml_signature=True, http_pull_model=True),
    "oadrCreatedPartyRegistration": dict(response=ok, ven_id="ven-1", registration_id="reg-1", vtn_id="VTN-1",
                                         profiles=profiles, requested_oadr_poll_freq=timedelta(seconds=10)),
    "oadrCancelPartyRegistration": dict(request_id="req-1", registration_id="reg-1", ven_id="ven-1"),
    "oadrCanceledPartyRegistration": dict(response=ok, registration_id="reg-1", ven_id="ven-1"),
    "oadrRequestReregistration": dict(ven_id="ven-1"),
    "oadrRequestEvent": dict(request_id="req-1", ven_id="ven-1"),
    "oadrDistributeEvent": dict(response=ok, request_id="req-2", vtn_id="VTN-1", events=[event]),
    "oadrCreatedEvent": dict(response=ok, ven_id="ven-1",
                             event_responses=[dict(response_code=200, response_description="OK", request_id="req-2",
                                                   event_id="ev-1", modification_number=2, opt_type="optIn")]),
    "oadrRegisterReport": dict(request_id="req-1", ven_id="ven-1", reports=[report]),
    "oadrRegisteredReport": dict(response=ok, ven_id="ven-1", report_requests=[request]),
    "oadrCreateReport": dict(request_id="req-1", ven_id="ven-1", report_requests=[request]),
    "oadrCreatedReport": dict(response=ok, ven_id="ven-1", pending_reports=[{"report_request_id": "rr-1"}]),
    "oadrUpdateReport": dict(request_id="req-1", ven_id="ven-1", reports=[data_report]),
    "oadrUpdatedReport": dict(response=ok, ven_id="ven-1"),
    "oadrCancelReport": dict(request_id="req-1", ven_id="ven-1", report_request_id="rr-1", report_to_follow=False),
    "oadrCanceledReport": dict(response=ok, ven_id="ven-1", pending_reports=[{"report_request_id": "rr-1"}]),
    "oadrCreateOpt": dict(opt_id="opt-1", opt_type="optOut", opt_reason="participating", ven_id="ven-1",
                          created_date_time=now, request_id="req-1", event_id="ev-1", modification_number=2,
                          targets=[{"ven_id": "ven-1"}]),
    "oadrCreatedOpt": dict(response=ok, opt_id="opt-1"),
    "oadrCancelOpt": dict(request_id="req-1", opt_id="opt-1", ven_id="ven-1"),
    "oadrCanceledOpt": dict(response=ok, opt_id="opt-1"),
    "oadrPoll": dict(ven_id="ven-1"),
    "oadrResponse": dict(response=ok, ven_id="ven-1"),
}

for name, payload in messages.items():
    try:
        msg = create_message(name, cert=cert, key=key, **payload)
    except Exception as err:
        print("PEER fail", name, f"{type(err).__name__}: {err}".replace("\n", " "), flush=True)
        continue
    with open(os.path.join(out, name + ".xml"), "w") as f:
        f.write(msg)
    print("PEER made", name, flush=True)

shutil.copytree(os.path.join(os.path.dirname(openleadr.__file__), "schema"), os.path.join(out, "schema"))
print("PEER done", flush=True)
