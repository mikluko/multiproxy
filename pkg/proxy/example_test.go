package proxy_test

import (
	"log"
	"net/http"
	"os"

	"sarak.sh/mikluko/multiproxy/pkg/middleware/headers"
	"sarak.sh/mikluko/multiproxy/pkg/proxy"
)

// A proxy that intercepts api.example.com, replacing the Authorization header on its requests, and tunnels every
// other host.
func ExampleNew() {
	h, err := proxy.New(proxy.Config{
		MITM:   []string{"api.example.com"},
		Tunnel: []string{"*"},
		Middleware: []func(http.Handler) http.Handler{
			headers.Rewrite(headers.Rule{
				Host: "api.example.com",
				Set:  http.Header{"Authorization": {"Bearer " + os.Getenv("API_TOKEN")}},
			}),
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", h))
}
