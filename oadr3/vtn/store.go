// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/cB-Sigma/openadr/oadr3"
)

// ErrNotFound is returned by a Store for an object it does not hold.
var ErrNotFound = errors.New("vtn: object not found")

// Store keeps the VTN's objects. The VTN serialises its writes and holds
// its own lock around every read and write, so a Store needs to be safe
// for concurrent readers only; it must not keep references to the objects
// it is given or hand out ones it keeps (copy them).
//
// Objects are JSON maps with "id", "objectType", "createdDateTime" and
// "modificationDateTime" set by the VTN; a durable store may simply keep
// their JSON by type and ID.
type Store interface {
	// Get gives one object, or ErrNotFound.
	Get(ctx context.Context, typ, id string) (Object, error)
	// List gives every object of a type, oldest first: by
	// createdDateTime, then id (the order paging works on).
	List(ctx context.Context, typ string) ([]Object, error)
	// Put creates or replaces an object (its "id" names it).
	Put(ctx context.Context, typ string, o Object) error
	// Delete removes an object; deleting a missing one is not an error.
	Delete(ctx context.Context, typ, id string) error
}

// MemoryStore is a Store in memory.
type MemoryStore struct {
	mu     sync.RWMutex
	byType map[string]map[string]Object
}

// NewMemoryStore makes an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{byType: map[string]map[string]Object{}}
}

// Get implements Store.
func (s *MemoryStore) Get(_ context.Context, typ, id string) (Object, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.byType[typ][id]
	if !ok {
		return nil, ErrNotFound
	}
	return oadr3.Clone(o), nil
}

// List implements Store.
func (s *MemoryStore) List(_ context.Context, typ string) ([]Object, error) {
	s.mu.RLock()
	out := make([]Object, 0, len(s.byType[typ]))
	for _, o := range s.byType[typ] {
		out = append(out, oadr3.Clone(o))
	}
	s.mu.RUnlock()
	SortObjects(out)
	return out, nil
}

// Put implements Store.
func (s *MemoryStore) Put(_ context.Context, typ string, o Object) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.byType[typ]
	if m == nil {
		m = map[string]Object{}
		s.byType[typ] = m
	}
	m[oadr3.Str(o, "id")] = oadr3.Clone(o)
	return nil
}

// Delete implements Store.
func (s *MemoryStore) Delete(_ context.Context, typ, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byType[typ], id)
	return nil
}

// SortObjects orders objects oldest first (createdDateTime, then id), as
// Store.List must.
func SortObjects(l []Object) {
	sort.SliceStable(l, func(i, j int) bool {
		a, b := oadr3.Str(l[i], "createdDateTime"), oadr3.Str(l[j], "createdDateTime")
		if a != b {
			return a < b
		}
		return oadr3.Str(l[i], "id") < oadr3.Str(l[j], "id")
	})
}
