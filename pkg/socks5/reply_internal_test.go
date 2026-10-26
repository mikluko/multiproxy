package socks5

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplyFor(t *testing.T) {
	for status, want := range map[int]byte{
		http.StatusOK:                  repSucceeded,
		http.StatusForbidden:           repNotAllowed,
		http.StatusMethodNotAllowed:    repNotAllowed,
		http.StatusBadGateway:          repUnreachable,
		http.StatusGatewayTimeout:      repTTLExpired,
		http.StatusInternalServerError: repFailure,
		0:                              repFailure,
	} {
		require.Equal(t, want, replyFor(status), "status %d", status)
	}
}

func TestStatusOf(t *testing.T) {
	for head, want := range map[string]int{
		"HTTP/1.1 200 OK":                  200,
		"HTTP/1.1 502 Bad Gateway\r\nX: y": 502,
		"HTTP/1.1 204":                     204,
		"garbage":                          0,
		"HTTP/1.1 abc Not A Number":        0,
	} {
		require.Equal(t, want, statusOf([]byte(head)), head)
	}
}
