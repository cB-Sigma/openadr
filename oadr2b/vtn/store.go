// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

import (
	"context"
	"slices"
	"strings"
	"sync"
	"time"
)

// Registration is what the VTN keeps about a registered VEN.
type Registration struct {
	VenID          string
	RegistrationID string
	VenName        string
	// Fingerprint is the VEN's TLS client certificate fingerprint, or the
	// fingerprint of the certificate it signed its registration with when
	// it came without a client certificate ("" when neither).
	Fingerprint      string
	ProfileName      string
	TransportName    string
	TransportAddress string
	// Push is true when the VEN registered with oadrHttpPullModel false:
	// the VTN posts to TransportAddress instead of waiting for polls.
	Push         bool
	ReportOnly   bool
	XMLSignature bool
	Registered   time.Time
}

// Store keeps registrations. Implementations must be safe for concurrent
// use. Get and ByFingerprint return nil and no error when there is none.
// The VTN keeps everything else (queued messages, events, report
// requests) in memory.
type Store interface {
	Get(ctx context.Context, venID string) (*Registration, error)
	ByFingerprint(ctx context.Context, fingerprint string) (*Registration, error)
	Put(ctx context.Context, r Registration) error
	Delete(ctx context.Context, venID string) error
	List(ctx context.Context) ([]Registration, error)
}

// MemoryStore is a Store in memory, the default.
type MemoryStore struct {
	mu   sync.Mutex
	regs map[string]Registration
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore { return &MemoryStore{regs: map[string]Registration{}} }

// Get implements Store.
func (m *MemoryStore) Get(_ context.Context, venID string) (*Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.regs[venID]; ok {
		return &r, nil
	}
	return nil, nil
}

// ByFingerprint implements Store.
func (m *MemoryStore) ByFingerprint(_ context.Context, fp string) (*Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.regs {
		if fp != "" && strings.EqualFold(r.Fingerprint, fp) {
			return &r, nil
		}
	}
	return nil, nil
}

// Put implements Store.
func (m *MemoryStore) Put(_ context.Context, r Registration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.regs[r.VenID] = r
	return nil
}

// Delete implements Store.
func (m *MemoryStore) Delete(_ context.Context, venID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.regs, venID)
	return nil
}

// List implements Store, ordered by venID.
func (m *MemoryStore) List(context.Context) ([]Registration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Registration, 0, len(m.regs))
	for _, r := range m.regs {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Registration) int { return strings.Compare(a.VenID, b.VenID) })
	return out, nil
}
