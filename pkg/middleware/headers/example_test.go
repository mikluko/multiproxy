package headers_test

import (
	"net/http"
	"os"

	"sarak.sh/mikluko/multiproxy/pkg/handlers"
	"sarak.sh/mikluko/multiproxy/pkg/middleware/headers"
	"sarak.sh/mikluko/multiproxy/pkg/router"
)

// A proxy that intercepts api.example.com and replaces the Authorization header on its requests. Any middleware
// plugs in the same way: MITMHandler.Handler serves each request intercepted from a CONNECT session.
func ExampleRewrite() {
	rewrite := headers.Rewrite(headers.Rule{
		Host: "api.example.com",
		Set:  http.Header{"Authorization": {"Bearer " + os.Getenv("API_TOKEN")}},
	})

	r := &router.Router{
		Default: rewrite(&handlers.HTTPHandler{}),
	}
	r.HandleConnectHost("api.example.com", &handlers.MITMHandler{
		Handler: rewrite(&handlers.HTTPHandler{}),
	})

	_ = http.ListenAndServe("127.0.0.1:8080", r)
}
