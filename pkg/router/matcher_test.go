package router

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatcher(t *testing.T) {
	t.Run("exact domain", func(t *testing.T) {
		m := matcher{
			tpl: "example.com",
		}
		require.True(t, m.matches("example.com"))
		require.False(t, m.matches("www.example.com"))
		require.False(t, m.matches("example.net"))
	})
	t.Run("domain suffix", func(t *testing.T) {
		m := matcher{
			tpl: ".example.com",
		}
		require.True(t, m.matches("example.com"))
		require.True(t, m.matches("www.example.com"))
		require.False(t, m.matches("example.net"))
	})
	t.Run("ip address", func(t *testing.T) {
		m := matcher{
			tpl: "127.0.0.1",
		}
		require.True(t, m.matches("127.0.0.1"))
		require.False(t, m.matches("127.0.0.2"))
		require.False(t, m.matches("localhost"))
		require.False(t, m.matches("example.com"))
	})
}
