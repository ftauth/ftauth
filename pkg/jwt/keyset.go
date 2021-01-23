package jwt

import "encoding/json"

// KeySet is a JSON Web Key set, used for representing
// multiple valid JWKs.
type KeySet struct {
	Keys []*Key `json:"keys"`
}

// NewKeySet creates a new KeySet from the given keys.
func NewKeySet(keys []*Key) *KeySet {
	return &KeySet{
		Keys: keys,
	}
}

// DecodeKeySet decodes a JSON-encoded key set.
func DecodeKeySet(keySet string) (*KeySet, error) {
	var _ks KeySet
	if err := json.Unmarshal([]byte(keySet), &_ks); err != nil {
		return nil, err
	}

	var keys []*Key
	for _, _key := range _ks.Keys {
		b, err := json.Marshal(_key)
		if err != nil {
			return nil, err
		}
		key, err := ParseJWK(string(b))
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return &KeySet{
		Keys: keys,
	}, nil
}
