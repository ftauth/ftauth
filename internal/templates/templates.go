package templates

import (
	"embed"
	"text/template"
)

// All holds all templates for FTAuth.
var All *template.Template

// SetupTemplates parses templates and sets a global variable with the output.
func SetupTemplates(fs embed.FS) error {
	var err error
	All, err = template.ParseFS(fs, "static/*.tmpl")
	return err
}
