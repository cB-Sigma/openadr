package oadr3

// The VTN's objects (programs, events, reports, subscriptions, vens,
// resources) and our own checks of client representations. Objects are
// kept as JSON maps so that content we do not interpret (private
// extensions, optional fields) is returned as it was written; the fields
// the VTN acts on are checked here whether or not the operator supplied
// the OpenAPI YAML.

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Object types (objectTypes enumeration).
const (
	TypeProgram      = "PROGRAM"
	TypeEvent        = "EVENT"
	TypeReport       = "REPORT"
	TypeSubscription = "SUBSCRIPTION"
	TypeVEN          = "VEN"
	TypeResource     = "RESOURCE"
)

// ObjectTypes lists every addressable object type.
var ObjectTypes = []string{TypeProgram, TypeEvent, TypeReport, TypeSubscription, TypeVEN, TypeResource}

// Operations named in subscriptions and notifications.
var Operations = []string{"READ", "CREATE", "UPDATE", "DELETE"}

// MaxLimit is the largest page the OpenAPI definition allows.
const MaxLimit = 50

// Object is one object's JSON representation.
type Object = map[string]any

// MetadataKeys are provisioned by the VTN; values in POST and PUT bodies
// are ignored (Definition, POST and PUT).
var MetadataKeys = []string{"id", "createdDateTime", "modificationDateTime", "objectType"}

func Str(o Object, k string) string {
	s, _ := o[k].(string)
	return s
}

func Strs(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Clone deep-copies an object (JSON round trip).
func Clone(o Object) Object {
	b, _ := json.Marshal(o)
	var c Object
	_ = json.Unmarshal(b, &c)
	return c
}

// ---- checks of client representations ------------------------------------

// Problem is a failed check answered with a problem object.
type Problem struct {
	Status int
	Title  string
	Detail string
}

func (e *Problem) Error() string { return e.Detail }

func BadRequest(format string, a ...any) error {
	return &Problem{Status: 400, Title: "Bad Request", Detail: fmt.Sprintf(format, a...)}
}

func Conflict(format string, a ...any) error {
	return &Problem{Status: 409, Title: "Conflict", Detail: fmt.Sprintf(format, a...)}
}

func Forbidden(format string, a ...any) error {
	return &Problem{Status: 403, Title: "Forbidden", Detail: fmt.Sprintf(format, a...)}
}

func NotFound(format string, a ...any) error {
	return &Problem{Status: 404, Title: "Not Found", Detail: fmt.Sprintf(format, a...)}
}

var objectIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

// durationRe is the ISO 8601 duration form the definition allows
// (optional sign, years, months, days or weeks, hours, minutes, seconds).
var durationRe = regexp.MustCompile(`^(-?)P(\d+Y)?(\d+M)?(\d+[DW])?(T(\d+H)?(\d+M)?(\d+(\.\d+)?S)?)?$`)

// ParseDuration reads an ISO 8601 duration; years and months count as
// 365 and 30 days. P9999Y and longer are reported as infinite.
func ParseDuration(s string) (d time.Duration, infinite bool, err error) {
	m := durationRe.FindStringSubmatch(s)
	if m == nil || s == "P" || s == "-P" || strings.HasSuffix(s, "T") {
		return 0, false, fmt.Errorf("%q is not an ISO 8601 duration", s)
	}
	num := func(part string) float64 {
		if part == "" {
			return 0
		}
		f, _ := strconv.ParseFloat(part[:len(part)-1], 64)
		return f
	}
	years := num(m[2])
	if years >= 9999 {
		return 0, true, nil
	}
	days := years*365 + num(m[3])*30
	if m[4] != "" {
		n := num(m[4])
		if strings.HasSuffix(m[4], "W") {
			n *= 7
		}
		days += n
	}
	secs := days*86400 + num(m[6])*3600 + num(m[7])*60 + num(m[8])
	if secs > float64(math.MaxInt64)/1e9 {
		return 0, true, nil
	}
	d = time.Duration(secs * float64(time.Second))
	if m[1] == "-" {
		d = -d
	}
	return d, false, nil
}

// ParseTime reads an RFC 3339 date-time; the definition's "now" marker
// (year 1, with or without a time) gives the zero time and now=true.
func ParseTime(s string) (t time.Time, now bool, err error) {
	if s == "0001-01-01" || strings.HasPrefix(s, "0001-01-01T00:00:00") {
		return time.Time{}, true, nil
	}
	t, err = time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("%q is not an RFC 3339 date-time", s)
	}
	return t, false, nil
}

func checkString(o Object, key string, required bool, maxLen int) error {
	v, present := o[key]
	if !present || v == nil {
		if required {
			return BadRequest("%s is required", key)
		}
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return BadRequest("%s must be a string", key)
	}
	if len(s) < 1 || (maxLen > 0 && len(s) > maxLen) {
		return BadRequest("%s must be 1 to %d characters", key, maxLen)
	}
	return nil
}

func checkStringList(o Object, key string, maxLen int) error {
	v, present := o[key]
	if !present || v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return BadRequest("%s must be a list", key)
	}
	for i, e := range list {
		s, ok := e.(string)
		if !ok || len(s) < 1 || len(s) > maxLen {
			return BadRequest("%s[%d] must be a string of 1 to %d characters", key, i, maxLen)
		}
	}
	return nil
}

func checkIntervalPeriod(v any, where string) error {
	if v == nil {
		return nil
	}
	p, ok := v.(map[string]any)
	if !ok {
		return BadRequest("%s must be an object", where)
	}
	if s, present := p["start"]; present && s != nil {
		ss, _ := s.(string)
		if _, _, err := ParseTime(ss); err != nil {
			return BadRequest("%s.start: %v", where, err)
		}
	}
	for _, k := range []string{"duration", "randomizeStart"} {
		if s, present := p[k]; present && s != nil {
			ss, _ := s.(string)
			if _, _, err := ParseDuration(ss); err != nil {
				return BadRequest("%s.%s: %v", where, k, err)
			}
		}
	}
	return nil
}

func checkValuesMaps(v any, where string) error {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return BadRequest("%s must be a list", where)
	}
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return BadRequest("%s[%d] must be an object", where, i)
		}
		if err := checkString(m, "type", true, 128); err != nil {
			return BadRequest("%s[%d]: %v", where, i, err)
		}
		vals, ok := m["values"].([]any)
		if !ok {
			return BadRequest("%s[%d].values is required and must be a list", where, i)
		}
		for j, x := range vals {
			switch y := x.(type) {
			case float64, string, bool:
			case map[string]any:
				_, okx := y["x"].(float64)
				_, oky := y["y"].(float64)
				if !okx || !oky {
					return BadRequest("%s[%d].values[%d] is an object but not a point {x, y}", where, i, j)
				}
			default:
				return BadRequest("%s[%d].values[%d] must be a number, string, boolean or point", where, i, j)
			}
		}
	}
	return nil
}

func checkIntervals(v any, where string) error {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return BadRequest("%s must be a list", where)
	}
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return BadRequest("%s[%d] must be an object", where, i)
		}
		id, ok := m["id"].(float64)
		if !ok || id != math.Trunc(id) || id < math.MinInt32 || id > math.MaxInt32 {
			return BadRequest("%s[%d].id is required and must be a 32-bit integer", where, i)
		}
		if err := checkIntervalPeriod(m["intervalPeriod"], fmt.Sprintf("%s[%d].intervalPeriod", where, i)); err != nil {
			return err
		}
		if _, ok := m["payloads"]; !ok {
			return BadRequest("%s[%d].payloads is required", where, i)
		}
		if err := checkValuesMaps(m["payloads"], fmt.Sprintf("%s[%d].payloads", where, i)); err != nil {
			return err
		}
	}
	return nil
}

func checkDescriptors(v any, where string, allowed ...string) error {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return BadRequest("%s must be a list", where)
	}
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return BadRequest("%s[%d] must be an object", where, i)
		}
		if err := checkString(m, "payloadType", true, 128); err != nil {
			return BadRequest("%s[%d]: %v", where, i, err)
		}
		if len(allowed) > 0 {
			ot, _ := m["objectType"].(string)
			if !slices.Contains(allowed, ot) {
				return BadRequest("%s[%d].objectType must be %s", where, i, strings.Join(allowed, " or "))
			}
		}
	}
	return nil
}

// CheckRequest checks a client's POST or PUT representation of typ and
// returns it without the VTN-provisioned metadata.
func CheckRequest(typ string, body Object) (Object, error) {
	o := Object{}
	for k, v := range body {
		if !slices.Contains(MetadataKeys, k) {
			o[k] = v
		}
	}
	// objectType is kept in ven and resource requests: there it names the
	// request form (BL_VEN_REQUEST, VEN_VEN_REQUEST, …).
	if typ == TypeVEN || typ == TypeResource {
		if v, ok := body["objectType"]; ok {
			o["objectType"] = v
		}
	}
	var err error
	switch typ {
	case TypeProgram:
		err = first(checkString(o, "programName", true, 128),
			checkIntervalPeriod(o["intervalPeriod"], "intervalPeriod"),
			checkDescriptors(o["payloadDescriptors"], "payloadDescriptors", "EVENT_PAYLOAD_DESCRIPTOR", "REPORT_PAYLOAD_DESCRIPTOR"),
			checkValuesMaps(o["attributes"], "attributes"), checkStringList(o, "targets", 128), checkProgramDescriptions(o["programDescriptions"]))
	case TypeEvent:
		err = first(checkObjectID(o, "programID", true), checkString(o, "eventName", false, 0), checkDurationField(o, "duration"),
			checkPriority(o["priority"]), checkStringList(o, "targets", 128),
			checkDescriptors(o["reportDescriptors"], "reportDescriptors"),
			checkDescriptors(o["payloadDescriptors"], "payloadDescriptors", "EVENT_PAYLOAD_DESCRIPTOR"),
			checkIntervalPeriod(o["intervalPeriod"], "intervalPeriod"), checkIntervals(o["intervals"], "intervals"))
	case TypeReport:
		err = first(checkObjectID(o, "eventID", true), checkString(o, "clientName", true, 128),
			checkDescriptors(o["payloadDescriptors"], "payloadDescriptors", "REPORT_PAYLOAD_DESCRIPTOR"), checkReportResources(o["resources"]))
	case TypeSubscription:
		err = first(checkString(o, "clientName", true, 128), checkObjectID(o, "programID", false),
			checkObjectOperations(o["objectOperations"]), checkStringList(o, "targets", 128))
	case TypeVEN:
		err = first(checkString(o, "venName", true, 128), checkValuesMaps(o["attributes"], "attributes"), checkStringList(o, "targets", 128))
		if err == nil {
			switch o["objectType"] {
			case "BL_VEN_REQUEST":
				err = checkString(o, "clientID", true, 128)
			case "VEN_VEN_REQUEST":
			default:
				err = BadRequest("objectType must be BL_VEN_REQUEST or VEN_VEN_REQUEST")
			}
		}
	case TypeResource:
		err = first(checkString(o, "resourceName", true, 128), checkObjectID(o, "venID", true),
			checkValuesMaps(o["attributes"], "attributes"), checkStringList(o, "targets", 128))
		if err == nil {
			switch o["objectType"] {
			case "BL_RESOURCE_REQUEST":
				err = checkString(o, "clientID", true, 128)
			case "VEN_RESOURCE_REQUEST":
			default:
				err = BadRequest("objectType must be BL_RESOURCE_REQUEST or VEN_RESOURCE_REQUEST")
			}
		}
	}
	return o, err
}

func first(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func checkObjectID(o Object, key string, required bool) error {
	v, present := o[key]
	if !present || v == nil {
		if required {
			return BadRequest("%s is required", key)
		}
		return nil
	}
	s, _ := v.(string)
	if !objectIDRe.MatchString(s) {
		return BadRequest("%s must be an object ID (1 to 128 letters, digits, _ or -)", key)
	}
	return nil
}

func checkDurationField(o Object, key string) error {
	v, present := o[key]
	if !present || v == nil {
		return nil
	}
	s, _ := v.(string)
	if _, _, err := ParseDuration(s); err != nil {
		return BadRequest("%s: %v", key, err)
	}
	return nil
}

func checkPriority(v any) error {
	if v == nil {
		return nil
	}
	f, ok := v.(float64)
	if !ok || f < 0 || f != math.Trunc(f) {
		return BadRequest("priority must be an integer of 0 or more")
	}
	return nil
}

func checkProgramDescriptions(v any) error {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return BadRequest("programDescriptions must be a list")
	}
	for i, e := range list {
		m, _ := e.(map[string]any)
		u, _ := m["URL"].(string)
		if len(u) < 2 || len(u) > 8000 {
			return BadRequest("programDescriptions[%d].URL is required (2 to 8000 characters)", i)
		}
	}
	return nil
}

func checkReportResources(v any) error {
	list, ok := v.([]any)
	if !ok {
		return BadRequest("resources is required and must be a list")
	}
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return BadRequest("resources[%d] must be an object", i)
		}
		if err := checkString(m, "resourceName", true, 128); err != nil {
			return BadRequest("resources[%d]: %v", i, err)
		}
		if err := checkIntervalPeriod(m["intervalPeriod"], fmt.Sprintf("resources[%d].intervalPeriod", i)); err != nil {
			return err
		}
		if _, ok := m["intervals"]; !ok {
			return BadRequest("resources[%d].intervals is required", i)
		}
		if err := checkIntervals(m["intervals"], fmt.Sprintf("resources[%d].intervals", i)); err != nil {
			return err
		}
	}
	return nil
}

func checkObjectOperations(v any) error {
	list, ok := v.([]any)
	if !ok {
		return BadRequest("objectOperations is required and must be a list")
	}
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return BadRequest("objectOperations[%d] must be an object", i)
		}
		objs, ok1 := m["objects"].([]any)
		ops, ok2 := m["operations"].([]any)
		cb, ok3 := m["callbackUrl"].(string)
		if !ok1 || !ok2 || !ok3 {
			return BadRequest("objectOperations[%d] needs objects, operations and callbackUrl", i)
		}
		for _, x := range objs {
			if s, _ := x.(string); !slices.Contains(ObjectTypes, s) {
				return BadRequest("objectOperations[%d].objects: %v is not an object type", i, x)
			}
		}
		for _, x := range ops {
			if s, _ := x.(string); !slices.Contains(Operations, s) {
				return BadRequest("objectOperations[%d].operations: %v is not READ, CREATE, UPDATE or DELETE", i, x)
			}
		}
		if len(cb) < 2 || len(cb) > 8000 {
			return BadRequest("objectOperations[%d].callbackUrl must be 2 to 8000 characters", i)
		}
		if bt, present := m["bearerToken"]; present && bt != nil {
			if _, ok := bt.(string); !ok {
				return BadRequest("objectOperations[%d].bearerToken must be a string", i)
			}
		}
	}
	return nil
}

// ---- event timing ----------------------------------------------------------

// Window gives the time an event covers: its start and end; open is true
// when the end is unbounded (P9999Y, or intervals without timing) and
// startsNow when the start is the "now" marker.
type Window struct {
	Start, End      time.Time
	Open, StartsNow bool
}

func Period(v any) (start time.Time, startSet, now bool, dur time.Duration, durSet, inf bool) {
	p, _ := v.(map[string]any)
	if s, ok := p["start"].(string); ok {
		t, n, err := ParseTime(s)
		if err == nil {
			start, startSet, now = t, !n, n
		}
	}
	if s, ok := p["duration"].(string); ok {
		d, i, err := ParseDuration(s)
		if err == nil {
			dur, durSet, inf = d, true, i
		}
	}
	return
}

// EventWindow works out an event's time span from its intervalPeriod,
// its intervals' own periods and its duration.
func EventWindow(ev Object) Window {
	w := Window{}
	s0, s0Set, now0, d0, d0Set, inf0 := Period(ev["intervalPeriod"])
	w.StartsNow = now0
	intervals, _ := ev["intervals"].([]any)
	var latest time.Time
	var earliest time.Time
	known := false
	for i, x := range intervals {
		iv, _ := x.(map[string]any)
		s, sSet, now, d, dSet, inf := Period(iv["intervalPeriod"])
		if now {
			w.StartsNow = true
		}
		if !sSet && s0Set {
			s, sSet = s0, true
			if d0Set && !inf0 {
				s = s0.Add(time.Duration(i) * d0)
			}
		}
		if !dSet {
			d, dSet, inf = d0, d0Set, inf0
		}
		if !sSet || !dSet {
			w.Open = true
			continue
		}
		if inf {
			w.Open = true
		}
		if !known || s.Before(earliest) {
			earliest = s
		}
		if e := s.Add(d); !known || e.After(latest) {
			latest = e
		}
		known = true
	}
	if !known && s0Set {
		earliest, known = s0, true
		if d0Set && !inf0 {
			latest = s0.Add(d0)
		} else {
			w.Open = true
		}
	}
	if !known {
		w.Open = true
	}
	if s, ok := ev["duration"].(string); ok && known {
		if d, inf, err := ParseDuration(s); err == nil {
			if inf {
				w.Open = true
			} else {
				latest, w.Open = earliest.Add(d), false
			}
		}
	}
	w.Start, w.End = earliest, latest
	return w
}

// Transpired is true when the event ended before now.
func Transpired(ev Object, now time.Time) bool {
	w := EventWindow(ev)
	return !w.Open && !w.StartsNow && !w.End.IsZero() && w.End.Before(now)
}

// CurrentInterval gives the interval of ev in effect at now, if any.
func CurrentInterval(ev Object, now time.Time) (map[string]any, bool) {
	s0, s0Set, now0, d0, d0Set, inf0 := Period(ev["intervalPeriod"])
	intervals, _ := ev["intervals"].([]any)
	for i, x := range intervals {
		iv, _ := x.(map[string]any)
		s, sSet, n, d, dSet, inf := Period(iv["intervalPeriod"])
		if n {
			return iv, true
		}
		if !sSet && s0Set {
			s, sSet = s0, true
			if d0Set && !inf0 {
				s = s0.Add(time.Duration(i) * d0)
			}
		}
		if !sSet && now0 && i == 0 {
			return iv, true
		}
		if !dSet {
			d, dSet, inf = d0, d0Set, inf0
		}
		if !sSet || now.Before(s) {
			continue
		}
		if !dSet || inf || now.Before(s.Add(d)) {
			return iv, true
		}
	}
	return nil, false
}
