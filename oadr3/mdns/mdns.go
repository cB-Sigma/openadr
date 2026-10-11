// Package mdns implements the local-VTN discovery of the OpenADR 3.1.0
// Definition (section "Discovery and Configuration of Local VTNs"): a VTN
// advertises the DNS-SD service type _openadr3._tcp over multicast DNS
// (RFC 6762, RFC 6763) and a VEN browses for it.
//
// The responder and browser are github.com/cB-Sigma/mdns; this package adds the service
// type, the VTN's TXT records and an Announce that renames the instance
// after a conflict ("Site gateway (2)") instead of failing.
package mdns

import (
	"context"
	"strconv"
	"strings"

	mdnslib "github.com/cB-Sigma/mdns"
)

// ServiceType is the DNS-SD service type an OpenADR 3 VTN advertises.
const ServiceType = "_openadr3._tcp"

// The responder and browser of github.com/cB-Sigma/mdns under the names this package has
// always had.
type (
	Announcer = mdnslib.Announcer
	Options   = mdnslib.Options
	Service   = mdnslib.Service
)

const (
	DefaultPort = mdnslib.DefaultPort
	DefaultWait = mdnslib.DefaultWait
)

// ErrConflict is returned by Announce when every renamed instance was
// taken too (RFC 6762 clause 9).
var ErrConflict = mdnslib.ErrConflict

// Announce advertises s as an instance of ServiceType (see
// mdnslib.Announce). When probing finds the instance name taken, it
// renames the instance with mdnslib.RenameInstance unless opts.Rename is
// set.
func Announce(ctx context.Context, s Service, opts Options) (*Announcer, error) {
	if opts.Rename == nil {
		opts.Rename = mdnslib.RenameInstance
	}
	return mdnslib.Announce(ctx, s, ServiceType, opts)
}

// Browse looks for instances of service (ServiceType for VTNs); see
// mdnslib.Browse.
func Browse(ctx context.Context, service string, opts Options) ([]Service, error) {
	return mdnslib.Browse(ctx, service, opts)
}

// VTNRecords builds the TXT metadata a local VTN advertises: version,
// base_path, local_url (https://{host}.local:{port}/{base_path}),
// program_names (comma separated), requires_auth (True or False) and
// openapi_url (left out when empty).
func VTNRecords(version, basePath, host string, port int, programNames []string, requiresAuth bool, openapiURL string) map[string]string {
	bp := strings.Trim(basePath, "/")
	u := "https://" + hostLabel(host) + ".local:" + strconv.Itoa(port)
	if bp != "" {
		u += "/" + bp
	}
	auth := "False"
	if requiresAuth {
		auth = "True"
	}
	m := map[string]string{
		"version":       version,
		"base_path":     bp,
		"local_url":     u,
		"program_names": strings.Join(programNames, ","),
		"requires_auth": auth,
	}
	if openapiURL != "" {
		m["openapi_url"] = openapiURL
	}
	return m
}

// hostLabel strips a trailing dot and ".local" from a host name.
func hostLabel(h string) string {
	h = strings.TrimSuffix(h, ".")
	if len(h) >= 6 && strings.EqualFold(h[len(h)-6:], ".local") {
		h = h[:len(h)-6]
	}
	return h
}
