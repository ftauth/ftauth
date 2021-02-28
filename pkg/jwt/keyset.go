package jwt

import (
	"encoding/json"
	"errors"
)

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

// KeyForAlgorithm returns the key in the set matching the given algorithm.
func (ks *KeySet) KeyForAlgorithm(alg Algorithm) (*Key, error) {
	for _, key := range ks.Keys {
		if key.Algorithm == alg {
			return key, nil
		}
	}
	return nil, errors.New("key not found")
}

// KeyForID returns the key in the set matching the given ID.
func (ks *KeySet) KeyForID(keyID string) (*Key, error) {
	for _, key := range ks.Keys {
		if key.KeyID == keyID {
			return key, nil
		}
	}
	return nil, errors.New("key not found")
}
