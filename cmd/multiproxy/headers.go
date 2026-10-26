package main

import (
	"fmt"
	"net/http"
	"strings"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/headers"
)

// headerFlag is a repeatable flag appending one headers.Rule per occurrence to rules: a Delete rule from
// HOST=Name where del is set, a Set rule from HOST=Name: value otherwise.
type headerFlag struct {
	rules *[]headers.Rule
	del   bool
}

func (f headerFlag) String() string { return "" }

func (f headerFlag) Set(s string) error {
	host, spec, ok := strings.Cut(s, "=")
	if !ok || host == "" {
		return fmt.Errorf("want HOST=%s, got %q", f.syntax(), s)
	}
	if f.del {
		name := strings.TrimSpace(spec)
		if !isToken(name) {
			return fmt.Errorf("want HOST=%s, got %q", f.syntax(), s)
		}
		*f.rules = append(*f.rules, headers.Rule{Host: host, Delete: []string{name}})
		return nil
	}
	name, value, ok := strings.Cut(spec, ":")
	name = strings.TrimSpace(name)
	if !ok || !isToken(name) {
		return fmt.Errorf("want HOST=%s, got %q", f.syntax(), s)
	}
	*f.rules = append(*f.rules, headers.Rule{
		Host: host,
		Set:  http.Header{http.CanonicalHeaderKey(name): {strings.TrimSpace(value)}},
	})
	return nil
}

func (f headerFlag) syntax() string {
	if f.del {
		return "Name"
	}
	return "Name: value"
}

// isToken reports whether s is a non-empty RFC 9110 token, the syntax of a header field name.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}
