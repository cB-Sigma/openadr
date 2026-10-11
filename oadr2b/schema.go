package oadr2b

// Optional XML Schema validation of OpenADR 2.0 messages.
//
// The OpenADR Alliance schemas are not ours to ship, so none of their
// content is in this repository: the operator supplies them at run time and
// github.com/cB-Sigma/xsd reads them then. The value (setting "schema") is a path to a
// zip archive or a directory, or "base64:<zip>" inline (the usual form in
// containers, which have no volumes). It may carry the 2.0a schema (root
// oadr_20a.xsd), the 2.0b schema (root oadr_20b.xsd) or both, found
// anywhere in the archive or directory tree; macOS resource entries are
// skipped.
//
// Contract with the rest of the package: the 2.0 transport code owns the
// settings "schema" and "schemaMode" and calls Check on every message it
// sends and receives, deciding from schemaMode what a failure means.
// LoadSchemas("") returns a nil set and Check on a nil set accepts
// everything, so an unconfigured deployment behaves as before.

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/cB-Sigma/xsd"
)

// Root namespaces of the two OpenADR 2.0 profiles.
const (
	NSOadr20a = "http://openadr.org/oadr-2.0a/2012/07"
	NSOadr20b = NSOadr
)

// Root schema documents of the two profiles.
const (
	schemaRoot20a = "oadr_20a.xsd"
	schemaRoot20b = "oadr_20b.xsd"
)

// SchemaSet holds the schema of each profile the operator supplied.
type SchemaSet struct {
	a, b *xsd.Schema
}

// LoadSchemas reads the schemas named by v (see the file comment).
func LoadSchemas(v string) (*SchemaSet, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	fsys, err := schemaFS(v)
	if err != nil {
		return nil, err
	}
	roots, err := findRoots(fsys)
	if err != nil {
		return nil, err
	}
	if roots[schemaRoot20a] == "" && roots[schemaRoot20b] == "" {
		return nil, fmt.Errorf("openadr schema: neither %s nor %s found", schemaRoot20a, schemaRoot20b)
	}
	s := &SchemaSet{}
	if p := roots[schemaRoot20a]; p != "" {
		if s.a, err = xsd.Load(fsys, p); err != nil {
			return nil, fmt.Errorf("openadr 2.0a schema: %w", err)
		}
	}
	if p := roots[schemaRoot20b]; p != "" {
		if s.b, err = xsd.Load(fsys, p); err != nil {
			return nil, fmt.Errorf("openadr 2.0b schema: %w", err)
		}
	}
	return s, nil
}

func schemaFS(v string) (fs.FS, error) {
	if rest, ok := strings.CutPrefix(v, "base64:"); ok {
		b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(rest), ""))
		if err != nil {
			return nil, fmt.Errorf("openadr schema: inline value is not base64: %w", err)
		}
		return zipFS(b)
	}
	st, err := os.Stat(v)
	if err != nil {
		return nil, fmt.Errorf("openadr schema: %w", err)
	}
	if st.IsDir() {
		return os.DirFS(v), nil
	}
	b, err := os.ReadFile(v)
	if err != nil {
		return nil, fmt.Errorf("openadr schema: %w", err)
	}
	return zipFS(b)
}

func zipFS(b []byte) (fs.FS, error) {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, fmt.Errorf("openadr schema: not a zip archive: %w", err)
	}
	return zr, nil
}

// findRoots locates each profile's root document; two candidates for the
// same root are ambiguous and refused.
func findRoots(fsys fs.FS) (map[string]string, error) {
	roots := map[string]string{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "__MACOSX" {
				return fs.SkipDir
			}
			return nil
		}
		base := path.Base(p)
		if base != schemaRoot20a && base != schemaRoot20b {
			return nil
		}
		if prev := roots[base]; prev != "" {
			return fmt.Errorf("openadr schema: %s found twice (%s and %s)", base, prev, p)
		}
		roots[base] = p
		return nil
	})
	return roots, err
}

// Check validates one message against the schema of its profile, chosen
// by the namespace of the root element. A nil set accepts everything.
func (s *SchemaSet) Check(body []byte) error {
	if s == nil {
		return nil
	}
	ns, err := RootNamespace(body)
	if err != nil {
		return err
	}
	var sch *xsd.Schema
	var profile string
	switch ns {
	case NSOadr20a:
		sch, profile = s.a, "2.0a"
	case NSOadr20b:
		sch, profile = s.b, "2.0b"
	default:
		return fmt.Errorf("openadr schema: root element namespace %q is neither OpenADR 2.0a nor 2.0b", ns)
	}
	if sch == nil {
		return fmt.Errorf("openadr schema: an OpenADR %s message arrived but no %s schema was supplied", profile, profile)
	}
	if err := sch.Validate(body); err != nil {
		return fmt.Errorf("openadr %s: %w", profile, err)
	}
	return nil
}

func RootNamespace(body []byte) (string, error) {
	d := xml.NewDecoder(bytes.NewReader(body))
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			return "", errors.New("openadr schema: empty document")
		}
		if err != nil {
			return "", fmt.Errorf("openadr schema: not XML: %w", err)
		}
		if se, ok := tok.(xml.StartElement); ok {
			return se.Name.Space, nil
		}
	}
}
