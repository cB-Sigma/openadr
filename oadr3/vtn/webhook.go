// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

// Webhook notifications. A subscription names, per group of object types
// and operations, a callback URL and optionally a bearer token. When an
// object changes, every subscription that may see it (the same privacy
// rules as a read, with the subscription's targets as the requested ones)
// gets a notification object {objectType, operation, object, targets}
// POSTed to its callback with "Authorization: Bearer <bearerToken>".
//
// Delivery here:
//   - callbacks are checked when a subscription is written: an absolute
//     https URL (http only with AllowHTTP), answering a GET carrying a
//     random echo parameter with 200 and that value in the body
//     (SkipEchoCheck turns this off);
//   - notifications go out from a queue per callback URL, in the order of
//     the changes, never while the VTN holds its locks;
//   - each is tried Retries times with doubling back-off; redirects are
//     not followed; private and loopback addresses are refused unless
//     AllowPrivate (checked on the address actually dialled);
//   - a callback that fails BrokenAfter deliveries in a row is marked
//     broken (Status) and skipped until its subscription is written again;
//   - every POST carries NotificationIDHeader (the same for every
//     notification of one change, and for retries, so a receiver can drop
//     duplicates) and, with SigningKey, SignatureHeader: an HMAC-SHA256 of
//     the timestamp and body. The signature is this package's extension,
//     not part of OpenADR 3; the bearer token is the definition's own
//     callback authentication.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/openadr/oadr3"
)

// Headers of webhook POSTs.
const (
	// NotificationIDHeader identifies the change a notification is about.
	NotificationIDHeader = "X-OpenADR-Notification-ID"
	// SignatureHeader carries "t=<unix seconds>,sha256=<hex HMAC>" over
	// "<t>.<body>" when WebhookConfig.SigningKey is set.
	SignatureHeader = "X-OpenADR-Signature"
)

// WebhookConfig configures webhook delivery.
type WebhookConfig struct {
	// Timeout of one POST or echo check (default 10 s).
	Timeout time.Duration
	// Retries is the number of attempts per notification (default 3).
	Retries int
	// Backoff is the wait before the second attempt, doubled after each
	// (default 500 ms).
	Backoff time.Duration
	// BrokenAfter failed deliveries in a row mark a callback broken
	// (default 5).
	BrokenAfter int
	// QueueSize is the most notifications waiting per callback (default
	// 256); more are dropped and reported to OnDeliveryError.
	QueueSize int
	// AllowHTTP accepts http:// callbacks (tests, local networks).
	AllowHTTP bool
	// AllowPrivate accepts callbacks on private, loopback and link-local
	// addresses.
	AllowPrivate bool
	// SkipEchoCheck accepts callbacks without the echo check.
	SkipEchoCheck bool
	// RootCAs verify callback servers (default: the system's).
	RootCAs *x509.CertPool
	// SigningKey, when set, signs every POST (SignatureHeader).
	SigningKey []byte
	// Client replaces the HTTP client (its redirect and dial rules are
	// then the caller's).
	Client *http.Client
}

// Delivery is one notification on its way to a callback or MQTT topic.
type Delivery struct {
	// ID is the notification ID, shared by every delivery of one change.
	ID             string
	SubscriptionID string
	// ClientID owns the subscription.
	ClientID string
	// URL is the callback ("" for MQTT).
	URL    string
	Bearer string
	// Topic is the MQTT topic ("" for a webhook).
	Topic        string
	Notification map[string]any
}

type deliverer struct {
	v      *VTN
	cfg    WebhookConfig
	client *http.Client

	mu       sync.Mutex
	queues   map[string]chan Delivery // by callback URL
	failures map[string]int           // "<subscription> <url>"
	broken   map[string]BrokenCallback
	closed   bool
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

func newDeliverer(v *VTN, cfg WebhookConfig) (*deliverer, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Retries <= 0 {
		cfg.Retries = 3
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = 500 * time.Millisecond
	}
	if cfg.BrokenAfter <= 0 {
		cfg.BrokenAfter = 5
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	d := &deliverer{v: v, cfg: cfg, queues: map[string]chan Delivery{}, failures: map[string]int{}, broken: map[string]BrokenCallback{}}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	d.client = cfg.Client
	if d.client == nil {
		dialer := &net.Dialer{Timeout: cfg.Timeout}
		dial := dialer.DialContext
		if !cfg.AllowPrivate {
			dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialPublic(ctx, dialer, network, addr)
			}
		}
		d.client = &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
				Proxy: nil, DialContext: dial, MaxIdleConnsPerHost: 4},
			// A redirect could lead to a private address.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return d, nil
}

// dialPublic refuses private, loopback and link-local addresses; the
// check is made on the address dialled, so a name resolving to a private
// address is refused too.
func dialPublic(ctx context.Context, dialer *net.Dialer, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("callback host %s has no address", host)
	}
	for _, ip := range ips {
		if PrivateIP(ip.IP) {
			return nil, fmt.Errorf("callback host %s resolves to a private address %s", host, ip.IP)
		}
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

// PrivateIP says whether ip is loopback, private, link-local, unspecified
// or multicast: an address webhook callbacks may not use by default.
func PrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast()
}

func (d *deliverer) close() {
	d.mu.Lock()
	d.closed = true
	for u, q := range d.queues {
		close(q)
		delete(d.queues, u)
	}
	d.mu.Unlock()
	d.cancel()
	d.wg.Wait()
}

// checkCallbacks applies the callback rules to a subscription.
func (d *deliverer) checkCallbacks(ctx context.Context, o Object) error {
	seen := map[string]bool{}
	for i, op := range listOf(o["objectOperations"]) {
		cb, _ := op["callbackUrl"].(string)
		u, err := url.Parse(cb)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return oadr3.BadRequest("objectOperations[%d].callbackUrl is not an absolute http(s) URL", i)
		}
		if u.Scheme != "https" && !d.cfg.AllowHTTP {
			return oadr3.BadRequest("objectOperations[%d].callbackUrl must use https", i)
		}
		if seen[cb] || d.cfg.SkipEchoCheck {
			continue
		}
		seen[cb] = true
		echo := newID() + newID()
		q := u.Query()
		q.Set("echo", echo)
		u.RawQuery = q.Encode()
		cctx, cancel := context.WithTimeout(ctx, d.cfg.Timeout)
		req, _ := http.NewRequestWithContext(cctx, http.MethodGet, u.String(), nil)
		resp, err := d.client.Do(req)
		if err != nil {
			cancel()
			return oadr3.BadRequest("callback %s did not answer the echo check: %v", cb, err)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), echo) {
			return oadr3.BadRequest("callback %s did not return the echo value with 200 OK (status %d)", cb, resp.StatusCode)
		}
	}
	return nil
}

// enqueue queues deliveries (MQTT ones are published right away, in
// order, from the caller's goroutine).
func (d *deliverer) enqueue(notes []Delivery) {
	for _, n := range notes {
		body, _ := json.Marshal(n.Notification)
		if val := d.v.cfg.Validator; val != nil {
			if err := val.Schema("notification", body); err != nil {
				d.v.log.Error("OpenADR 3 notification fails the OpenAPI definition; not sent", "error", err)
				continue
			}
		}
		if n.Topic != "" {
			if err := d.v.cfg.MQTT.Publisher.Publish(d.ctx, n.Topic, body); err != nil {
				d.fail(n, err)
			}
			continue
		}
		d.mu.Lock()
		if d.closed {
			d.mu.Unlock()
			return
		}
		key := n.SubscriptionID + " " + n.URL
		if _, broken := d.broken[key]; broken {
			d.mu.Unlock()
			continue
		}
		q := d.queues[n.URL]
		if q == nil {
			q = make(chan Delivery, d.cfg.QueueSize)
			d.queues[n.URL] = q
			d.wg.Add(1)
			go d.worker(n.URL, q)
		}
		select {
		case q <- n:
			d.mu.Unlock()
		default:
			d.mu.Unlock()
			d.fail(n, fmt.Errorf("the queue for %s is full; notification dropped", n.URL))
		}
	}
}

func (d *deliverer) fail(n Delivery, err error) {
	d.v.log.Warn("OpenADR 3 notification not delivered", "callback", n.URL, "topic", n.Topic, "error", err)
	if f := d.v.cfg.OnDeliveryError; f != nil {
		f(n, err)
	}
}

// workerIdle is how long a callback's worker waits for work before it
// ends (a new notification starts another).
var workerIdle = 2 * time.Minute

// worker delivers one callback's notifications in order.
func (d *deliverer) worker(u string, q chan Delivery) {
	defer d.wg.Done()
	idle := time.NewTimer(workerIdle)
	defer idle.Stop()
	for {
		var n Delivery
		var ok bool
		select {
		case n, ok = <-q:
			if !ok {
				return
			}
		case <-idle.C:
			d.mu.Lock()
			if len(q) == 0 && d.queues[u] == q {
				delete(d.queues, u)
				d.mu.Unlock()
				return
			}
			d.mu.Unlock()
			idle.Reset(workerIdle)
			continue
		}
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(workerIdle)
		d.deliver(n)
	}
}

// deliver sends one notification and keeps the failure count.
func (d *deliverer) deliver(n Delivery) {
	key := n.SubscriptionID + " " + n.URL
	d.mu.Lock()
	_, broken := d.broken[key]
	d.mu.Unlock()
	if broken {
		return
	}
	err := d.post(n)
	d.mu.Lock()
	if err == nil {
		delete(d.failures, key)
		d.mu.Unlock()
		return
	}
	d.failures[key]++
	if d.failures[key] >= d.cfg.BrokenAfter {
		d.broken[key] = BrokenCallback{SubscriptionID: n.SubscriptionID, URL: n.URL, Since: d.v.now()}
		delete(d.failures, key)
	}
	d.mu.Unlock()
	d.fail(n, err)
}

// rewritten clears the broken marks of a subscription that was written.
func (d *deliverer) rewritten(subID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, b := range d.broken {
		if b.SubscriptionID == subID {
			delete(d.broken, k)
		}
	}
	for k := range d.failures {
		if strings.HasPrefix(k, subID+" ") {
			delete(d.failures, k)
		}
	}
}

func (d *deliverer) status() ([]BrokenCallback, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []BrokenCallback
	for _, b := range d.broken {
		out = append(out, b)
	}
	n := 0
	for _, q := range d.queues {
		n += len(q)
	}
	return out, n
}

// Sign gives the SignatureHeader value for body at time t with key: a
// receiver recomputes it to check a notification.
func Sign(key, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(ts + "."))
	m.Write(body)
	return "t=" + ts + ",sha256=" + hex.EncodeToString(m.Sum(nil))
}

// VerifySignature checks a SignatureHeader value against body with key,
// refusing timestamps more than maxAge away from now.
func VerifySignature(key, body []byte, header string, now time.Time, maxAge time.Duration) bool {
	var ts string
	for _, part := range strings.Split(header, ",") {
		if k, x, ok := strings.Cut(part, "="); ok && k == "t" {
			ts = x
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	t := time.Unix(sec, 0)
	if d := now.Sub(t); d > maxAge || d < -maxAge {
		return false
	}
	return hmac.Equal([]byte(Sign(key, body, t)), []byte(header))
}

func (d *deliverer) post(n Delivery) error {
	body, _ := json.Marshal(n.Notification)
	wait := d.cfg.Backoff
	var err error
	for attempt := 0; attempt < d.cfg.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-d.ctx.Done():
				return d.ctx.Err()
			case <-time.After(wait):
			}
			wait *= 2
		}
		req, _ := http.NewRequestWithContext(d.ctx, http.MethodPost, n.URL, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(NotificationIDHeader, n.ID)
		if n.Bearer != "" {
			req.Header.Set("Authorization", "Bearer "+n.Bearer)
		}
		if d.cfg.SigningKey != nil {
			req.Header.Set(SignatureHeader, Sign(d.cfg.SigningKey, body, d.v.now()))
		}
		var resp *http.Response
		resp, err = d.client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		err = fmt.Errorf("callback answered %d", resp.StatusCode)
	}
	return err
}
