package panel

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// staticFS holds the panel's stylesheet and scripts, including the
// vendored htmx build. They are embedded so a release is one binary and
// the panel never loads anything from a CDN.
//
//go:embed static
var staticFS embed.FS

// staticHandler serves the embedded assets under /panel/static/. It is
// deliberately public: the login page loads app.css before anybody has
// signed in. Directory listings are refused.
func (p *Panel) staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// The embed directive guarantees the subtree exists.
		panic("panel: embedded static directory is missing: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enabled, _ := p.auth()
		if !enabled {
			p.handleNotFound(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/") {
			p.handleNotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		files.ServeHTTP(w, r)
	})
}
