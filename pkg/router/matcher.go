package router

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

type matcher struct {
	tpl      string
	handler  http.Handler
	isSuffix bool
	isIP     bool
	once     sync.Once
}

func (m *matcher) init() {
	m.isSuffix = strings.HasPrefix(m.tpl, ".")
	m.isIP = net.ParseIP(m.tpl) != nil
}

func (m *matcher) matches(hostname string) bool {
	m.once.Do(m.init)
	switch {
	case m.isIP:
		return m.matchesIP(hostname)
	case m.isSuffix:
		return m.matchesSuffix(hostname)
	default:
		return m.matchesExact(hostname)
	}
}

func (m *matcher) matchesIP(ip string) bool {
	return m.matchesExact(ip)
}

func (m *matcher) matchesSuffix(hostname string) bool {
	if len(hostname) == len(m.tpl)-1 {
		return strings.HasSuffix(m.tpl, hostname)
	}
	return strings.HasSuffix(hostname, m.tpl)
}

func (m *matcher) matchesExact(hostname string) bool {
	return hostname == m.tpl
}

// MatchHost reports whether hostname matches pattern, under the syntax of Router.HandleConnectHost. The pattern
// "*" matches every hostname.
func MatchHost(pattern, hostname string) bool {
	if pattern == "*" {
		return true
	}
	m := matcher{tpl: pattern}
	return m.matches(hostname)
}
