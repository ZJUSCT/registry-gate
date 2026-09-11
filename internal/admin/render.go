package admin

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFS embed.FS

// pageNames are the templates (besides the shared layout) this package serves.
var pageNames = []string{"login", "dashboard", "user", "error"}

// templates holds one parsed template set per page (each page defines
// "content" over the shared "layout").
type templates struct {
	pages map[string]*template.Template
}

func parseTemplates() (*templates, error) {
	t := &templates{pages: make(map[string]*template.Template, len(pageNames))}
	for _, name := range pageNames {
		set, err := template.New("layout").ParseFS(templateFS,
			"templates/layout.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("admin: parse template %s: %w", name, err)
		}
		t.pages[name] = set
	}
	return t, nil
}

// render writes the page with the given HTTP status.
func (s *server) render(w http.ResponseWriter, status int, page string, data any) {
	t, ok := s.tmpl.pages[page]
	if !ok {
		http.Error(w, "admin: unknown page "+page, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("admin: render page", "page", page, "err", err)
	}
}
