// Package web serves the shared static assets (stylesheet) of the portal and
// admin UIs. The assets are embedded at build time; templates live next to
// the packages that render them (internal/portal/templates,
// internal/admin/templates) because go:embed cannot cross package boundaries.
package web

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var static embed.FS

// Handler serves the embedded static assets over HTTP. Mount it under a
// "{base}/static/" route.
func Handler() http.Handler {
	sub, err := fs.Sub(static, "static")
	if err != nil {
		panic("web: embedded static fs missing: " + err.Error())
	}
	return http.StripPrefix("/static/", http.FileServerFS(sub))
}
