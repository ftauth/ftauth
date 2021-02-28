package model

import (
	"embed"
	"io"
	"path/filepath"
	"strings"
)

//go:embed gql/schema
var schemaFS embed.FS

// Schema returns the GraphQL schema for FTAuth.
func Schema() (string, error) {
	bldr := strings.Builder{}

	const path = "gql/schema"

	// Load all relevant files
	ents, err := schemaFS.ReadDir(path)
	if err != nil {
		return "", err
	}
	for _, ent := range ents {
		filename := ent.Name()
		file, err := schemaFS.Open(filepath.Join(path, filename))
		if err != nil {
			return "", err
		}
		cont, err := io.ReadAll(file)
		if err != nil {
			return "", err
		}
		_, err = bldr.Write(cont)
		if err != nil {
			return "", err
		}
		err = bldr.WriteByte('\n')
		if err != nil {
			return "", err
		}
	}

	return bldr.String(), nil
}
