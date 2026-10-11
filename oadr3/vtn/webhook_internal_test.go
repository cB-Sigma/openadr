// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// A callback's worker ends when idle and a new one starts for the next
// notification.
func TestWorkerIdleExit(t *testing.T) {
	old := workerIdle
	workerIdle = 20 * time.Millisecond
	defer func() { workerIdle = old }()
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { got.Add(1) }))
	defer srv.Close()
	v, err := New(Config{AnonymousRead: true, Webhooks: WebhookConfig{AllowHTTP: true, AllowPrivate: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	send := func() {
		v.hooks.enqueue([]Delivery{{ID: "n", SubscriptionID: "s", URL: srv.URL, Notification: map[string]any{"operation": "CREATE"}}})
	}
	queues := func() int {
		v.hooks.mu.Lock()
		defer v.hooks.mu.Unlock()
		return len(v.hooks.queues)
	}
	send()
	for deadline := time.Now().Add(2 * time.Second); queues() != 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the idle worker did not end")
		}
	}
	send()
	for deadline := time.Now().Add(2 * time.Second); got.Load() != 2; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d deliveries", got.Load())
		}
	}
}
