// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/cB-Sigma/openadr/oadr2b"
)

// ServerTLSConfig is a server TLS configuration for a VTN: the TLS
// profile (oadr2b.TLSProfileOpenADR for exactly the two mandated suites
// over TLS 1.2, or oadr2b.TLSProfileCompatible), the VTN's certificates
// (an ECC and an RSA one may both be given; Go presents the one that
// suits the client), and client certificates required and checked
// against clientCAs. The client certificate's fingerprint then identifies
// the VEN.
func ServerTLSConfig(profile string, clientCAs *x509.CertPool, certs ...tls.Certificate) (*tls.Config, error) {
	if len(certs) == 0 {
		return nil, errors.New("a VTN needs a certificate")
	}
	for _, c := range certs {
		if err := oadr2b.CheckKeySize(c); err != nil {
			return nil, err
		}
	}
	tc := &tls.Config{Certificates: certs, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	if err := oadr2b.ApplyTLSProfile(tc, profile); err != nil {
		return nil, err
	}
	return tc, nil
}

// Serve answers on ln until ctx ends, over TLS when tc is not nil, and
// then shuts down (waiting up to five seconds for requests in progress).
func (v *VTN) Serve(ctx context.Context, ln net.Listener, tc *tls.Config) error {
	if tc != nil {
		ln = tls.NewListener(ln, tc)
	}
	srv := &http.Server{Handler: v, ReadHeaderTimeout: 10 * time.Second}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(sctx)
			cancel()
		case <-done:
		}
	}()
	err := srv.Serve(ln)
	close(done)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ListenAndServeTLS listens on addr and serves until ctx ends; tc is
// typically from ServerTLSConfig (nil serves plain HTTP, for tests).
func (v *VTN) ListenAndServeTLS(ctx context.Context, addr string, tc *tls.Config) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return v.Serve(ctx, ln, tc)
}
