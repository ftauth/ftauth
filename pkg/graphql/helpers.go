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

var timeTyp = reflect.TypeOf(time.Time{})
var marshallerTyp = reflect.TypeOf((*Marshaller)(nil)).Elem()

// MarshalGQL returns the GraphQL representation of v.
func MarshalGQL(v interface{}) string {
	if v == nil {
		return ""
	}
	if v, ok := v.(Marshaller); ok {
		return v.GQL()
	}

	typ := reflect.TypeOf(v)
	switch typ.Kind() {
	case reflect.String:
		return fmt.Sprintf(`"%s"`, v)
	case reflect.Array, reflect.Slice:
		val := typ.Elem()
		if val.Implements(marshallerTyp) {
			arr := reflect.ValueOf(v)
			var vars []string
			for i := 0; i < arr.Len(); i++ {
				m := arr.Index(i).Interface().(Marshaller)
				vars = append(vars, m.GQL())
			}
			return "[" + strings.Join(vars, ",") + "]"
		}
	case timeTyp.Kind():
		val := reflect.ValueOf(v)
		if t, ok := val.Interface().(time.Time); ok {
			return "\"" + t.Format(time.RFC3339) + "\""
		}
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
