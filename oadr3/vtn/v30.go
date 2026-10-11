// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package vtn

// OpenADR 3.0. Its objects and paths are those of 3.1 with these
// differences, which the VTN translates at its edge so that the rules
// above apply unchanged:
//   - targets are lists of {type, values} (valuesMap) instead of lists of
//     strings; they are kept as "TYPE:value" strings and given back in
//     the 3.0 form;
//   - searches name targets with targetType and targetValues;
//   - ven and resource requests carry no request form (BL_VEN_REQUEST, …):
//     the caller's role decides, and business logic need not name a
//     client ID;
//   - there is one read scope, read_all (RoleScopes30), and no MQTT
//     notifier.

import (
	"strings"

	"github.com/cB-Sigma/openadr/oadr3"
)

// target30 is the stored form of one 3.0 target value.
func target30(typ, value string) string { return typ + ":" + value }

// targetsIn turns 3.0 targets into stored strings; anything else is left
// for the checks to refuse.
func targetsIn(x any) any {
	l, ok := x.([]any)
	if !ok {
		return x
	}
	out := []any{}
	for _, e := range l {
		m, ok := e.(map[string]any)
		if !ok {
			return x
		}
		t, _ := m["type"].(string)
		vals, ok := m["values"].([]any)
		if t == "" || !ok {
			return x
		}
		for _, val := range vals {
			s, ok := val.(string)
			if !ok {
				return x
			}
			out = append(out, target30(t, s))
		}
	}
	return out
}

// targetsOut turns stored targets into the 3.0 form.
func targetsOut(x any) any {
	l := strs(x)
	if x == nil {
		return nil
	}
	out := []any{}
	idx := map[string]int{}
	for _, s := range l {
		t, val, ok := strings.Cut(s, ":")
		if !ok {
			t, val = "TARGET", s
		}
		i, seen := idx[t]
		if !seen {
			i = len(out)
			idx[t] = i
			out = append(out, map[string]any{"type": t, "values": []any{}})
		}
		m := out[i].(map[string]any)
		m["values"] = append(m["values"].([]any), val)
	}
	return out
}

// in adapts a client's representation to the stored form.
func (v *VTN) in(typ string, p *Principal, body Object) Object {
	if v.cfg.Version != Version30 {
		return body
	}
	o := Object{}
	for k, x := range body {
		o[k] = x
	}
	if x, ok := o["targets"]; ok && x != nil {
		o["targets"] = targetsIn(x)
	}
	switch typ {
	case oadr3.TypeVEN:
		o["objectType"] = "VEN_VEN_REQUEST"
	case oadr3.TypeResource:
		o["objectType"] = "VEN_RESOURCE_REQUEST"
	}
	return o
}

// out gives an object in the version's form.
func (v *VTN) out(typ string, o Object) Object {
	if v.cfg.Version != Version30 || o == nil {
		return o
	}
	c := oadr3.Clone(o)
	if x, ok := c["targets"]; ok && x != nil {
		c["targets"] = targetsOut(x)
	}
	return c
}

func (v *VTN) outList(typ string, l []Object) []Object {
	if v.cfg.Version != Version30 {
		return l
	}
	out := make([]Object, len(l))
	for i, o := range l {
		out[i] = v.out(typ, o)
	}
	return out
}
