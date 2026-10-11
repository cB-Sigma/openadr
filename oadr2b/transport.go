package oadr2b

// Simple HTTP details shared by both kinds (2.0b profile section 9.1):
// POST only (other methods 501), Content-Type application/xml with UTF-8
// (anything else 406), a payload that does not parse or does not validate
// against the schema is 406, Content-Length on every message and never a
// chunked body, and a response compressed with gzip or deflate when the
// request's Accept-Encoding asks for it (9.1.9.2). Push requests from a
// VTN are never compressed (9.1.9.3).

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// MaxBody is the largest message body read, sent or received.
const MaxBody = 1 << 20

// ContentType is the simple-HTTP media type.
const ContentType = "application/xml"

// MinRequestTimeout is 9.1.6's lower bound for HTTP client timeouts.
const MinRequestTimeout = 5 * time.Second

// ContentTypeOK accepts application/xml (text/xml too, as it is the same
// document type) with no charset or UTF-8.
func ContentTypeOK(v string) bool {
	mt, params, err := mime.ParseMediaType(v)
	if err != nil || (mt != ContentType && mt != "text/xml") {
		return false
	}
	cs, ok := params["charset"]
	return !ok || strings.EqualFold(cs, "utf-8")
}

// ReadRequest checks method and content type and reads the body. It
// answers the transport error itself and returns ok false.
func ReadRequest(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "OpenADR simple HTTP takes POST only", http.StatusNotImplemented)
		return nil, false
	}
	if !ContentTypeOK(r.Header.Get("Content-Type")) {
		http.Error(w, "the content type must be application/xml", http.StatusNotAcceptable)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		http.Error(w, "the request body is unreadable or larger than 1 MiB", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

// WriteXML answers with a payload: Content-Type, Content-Length and, when
// the client accepts it, gzip or deflate content encoding.
func WriteXML(w http.ResponseWriter, r *http.Request, b []byte) {
	enc := ""
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, q, _ := strings.Cut(strings.TrimSpace(part), ";")
		if qv := strings.TrimPrefix(strings.ReplaceAll(q, " ", ""), "q="); qv != q {
			if f, err := strconv.ParseFloat(qv, 64); err == nil && f == 0 {
				continue
			}
		}
		if name = strings.ToLower(strings.TrimSpace(name)); name == "gzip" || name == "deflate" {
			enc = name
			break
		}
	}
	if enc != "" {
		var buf bytes.Buffer
		var zw io.WriteCloser
		if enc == "gzip" {
			zw = gzip.NewWriter(&buf)
		} else {
			zw = zlib.NewWriter(&buf)
		}
		_, _ = zw.Write(b)
		_ = zw.Close()
		b = buf.Bytes()
		w.Header().Set("Content-Encoding", enc)
		w.Header().Add("Vary", "Accept-Encoding")
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	_, _ = w.Write(b)
}

// PostXML sends one payload and reads the answer. Go's transport asks for
// gzip and undoes it; the request carries Content-Length (the body is a
// byte slice, never chunked).
func PostXML(ctx context.Context, c *http.Client, url string, b []byte) ([]byte, *tls.ConnectionState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("Accept", ContentType)
	resp, err := c.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	if resp.StatusCode/100 != 2 {
		// Any 2xx is delivered (202 or 204 with no body: a transport-level
		// acknowledgement).
		return nil, resp.TLS, &HTTPError{Status: resp.StatusCode}
	}
	return body, resp.TLS, nil
}

// HTTPError is a transport-level refusal (9.1.5).
type HTTPError struct{ Status int }

func (e *HTTPError) Error() string {
	return fmt.Sprintf("the peer answered HTTP %d %s", e.Status, http.StatusText(e.Status))
}

// Retryable is whether 9.1.5 allows sending the request again: 404, 406
// and 501 must not be re-sent unchanged.
func (e *HTTPError) Retryable() bool {
	switch e.Status {
	case http.StatusNotFound, http.StatusNotAcceptable, http.StatusNotImplemented:
		return false
	}
	return true
}
