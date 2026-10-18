// Package strict rejects duplicate keys, case aliases, unknown fields and trailing JSON.
package strict

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

var ErrJSON = errors.New("INVALID_JSON")

func Decode(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := walk(d); err != nil {
		return ErrJSON
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrJSON
	}
	var raw any
	if json.Unmarshal(data, &raw) != nil {
		return ErrJSON
	}
	if !shape(raw, reflect.TypeOf(out).Elem()) {
		return ErrJSON
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrJSON
	}
	return nil
}
func walk(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || seen[s] {
				return ErrJSON
			}
			seen[s] = true
			if e = walk(d); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = walk(d); e != nil {
				return e
			}
		}
	default:
		return ErrJSON
	}
	_, e = d.Token()
	return e
}
func shape(v any, t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		return shape(v, t.Elem())
	}
	if v == nil {
		return false
	}
	switch t.Kind() {
	case reflect.Struct:
		// Standard text-marshaled types (e.g. time.Time) are scalar JSON strings.
		if _, ok := reflect.New(t).Interface().(json.Unmarshaler); ok {
			return true
		}
		m, ok := v.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			key := strings.Split(f.Tag.Get("json"), ",")[0]
			if key == "" {
				key = f.Name
			}
			if key != "-" {
				fields[key] = f.Type
			}
		}
		for k, x := range m {
			ft, ok := fields[k]
			if !ok || !shape(x, ft) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		a, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range a {
			if !shape(x, t.Elem()) {
				return false
			}
		}
	}
	return true
}
