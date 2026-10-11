# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# The openleadr-rs client library (openleadr-client, Apache-2.0 OR MIT,
# github.com/OpenLEADR/openleadr-rs) and its own integration tests, built
# at a pinned tag and commit, to run those tests against another VTN: they
# read OPENADR_VTN_URL and OPENLEADR_RS_VTN_URL and then log in with the
# client credentials admin/admin. sqlx's test harness still wants a
# PostgreSQL server (DATABASE_URL) for its per-test databases. Nothing of
# openleadr-rs is redistributed here.
FROM rust:1.94-alpine
RUN apk add --no-cache git cmake g++ make openssl-dev
RUN git clone --depth 1 --branch v0.2.6 https://github.com/OpenLEADR/openleadr-rs.git /app \
 && test "$(git -C /app rev-parse HEAD)" = "b20d616d9bbf511a48314e127844a240e0349a17"
WORKDIR /app
ENV SQLX_OFFLINE=true RUSTFLAGS="-Ctarget-feature=-crt-static"
RUN cargo test -p openleadr-client --no-run
ENTRYPOINT ["sleep"]
CMD ["3600"]
