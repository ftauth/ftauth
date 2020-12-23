package sqlutil

import "strings"

// ParseArray parses an array stored as a string.
func ParseArray(arr string) []string {
	return strings.Split(strings.Trim(arr, "{}"), ",")
}
