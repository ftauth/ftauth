package graphql

import (
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Marshaller defines an ability for a type to represent itself in GraphQL.
type Marshaller interface {
	GQL() string
}

var marshallerTyp = reflect.TypeOf((*Marshaller)(nil)).Elem()

// MarshalGQL returns the GraphQL representation of v.
func MarshalGQL(v interface{}) string {
	if v == nil {
		return ""
	}
	if v, ok := v.(Marshaller); ok {
		return v.GQL()
	}

	switch v.(type) {
	case string:
		return fmt.Sprintf(`"%s"`, v)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", v)
	case float32, float64:
		return fmt.Sprintf("%f", v)
	case map[string]interface{}:
		var lines []string
		for k, v := range v.(map[string]interface{}) {
			lines = append(lines, fmt.Sprintf("%s: %s", k, MarshalGQL(v)))
		}
		return "{" + strings.Join(lines, "\n") + "}"
	case time.Time:
		return "\"" + v.(time.Time).Format(time.RFC3339) + "\""
	case *time.Time:
		return "\"" + v.(*time.Time).Format(time.RFC3339) + "\""
	}

	typ := reflect.TypeOf(v)
	switch typ.Kind() {
	case reflect.Array, reflect.Slice:
		val := typ.Elem()
		arr := reflect.ValueOf(v)
		var vars []string
		for i := 0; i < arr.Len(); i++ {
			v := arr.Index(i).Interface()
			if val.Implements(marshallerTyp) {
				m := v.(Marshaller)
				vars = append(vars, m.GQL())
			} else {
				vars = append(vars, MarshalGQL(v))
			}
		}
		return "[" + strings.Join(vars, ",") + "]"
	}

	return fmt.Sprintf("%v", v)
}

// BuildGraphQLEnumArray creates an array for values which can be represented
// as enums in GraphQL, i.e. do not need to be surrounded by strings.
func BuildGraphQLEnumArray(v interface{}) string {
	if v == nil {
		return "[]"
	}
	var vars []string
	switch t := v.(type) {
	case []string:
		vars = t
	case string:
		vars = append(vars, t)
	default:
		typ := reflect.TypeOf(v)
		if typ.Kind() == reflect.Array || typ.Kind() == reflect.Slice {
			arr := reflect.ValueOf(v)
			for i := 0; i < arr.Len(); i++ {
				vars = append(vars, arr.Index(i).String())
			}
		}
	}
	return "[" + strings.Join(vars, ",") + "]"
}

// BuildGraphQLArray builds a GraphQL array for including in queries or mutations.
func BuildGraphQLArray(arr []string) string {
	var quoted []string
	for _, str := range arr {
		quoted = append(quoted, "\""+str+"\"")
	}
	return "[" + strings.Join(quoted, ",") + "]"
}
