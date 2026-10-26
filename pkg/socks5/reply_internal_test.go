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
