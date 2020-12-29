package sqlutil

import (
	"fmt"
	"strings"
)

// ParseArray parses an array stored as a string.
func ParseArray(arr string) []string {
	fields := strings.Split(arr, ",")
	var values []string
	for _, field := range fields {
		value := strings.Trim(field, "{'}")
		if value != "" {
			values = append(values, value)
		}
	}
	return values
}

// GenerateArrayString creates a string from an array for storing in an SQL database.
func GenerateArrayString(arr []string) string {
	var sb strings.Builder
	sb.WriteString("{")
	var escaped []string
	for _, item := range arr {
		escaped = append(escaped, fmt.Sprintf("'%s'", item))
	}
	sb.WriteString(strings.Join(escaped, ","))
	sb.WriteString("}")
	return sb.String()
}
