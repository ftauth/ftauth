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
		values = append(values, strings.Trim(field, "{'}"))
	}
	return values
}

// GenerateArrayString creates a string from an array for storing in an SQL database.
func GenerateArrayString(arr []string) string {
	var sb strings.Builder
	sb.WriteString("{")
	for _, item := range arr {
		sb.WriteString(fmt.Sprintf("'%s'", item))
	}
	sb.WriteString("}")
	return sb.String()
}
