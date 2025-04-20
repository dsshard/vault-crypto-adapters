package types

import "errors"

type KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Address    string `json:"address"`
}

type KeyManager struct {
	ServiceName string     `json:"service_name"`
	KeyPairs    []*KeyPair `json:"key_pairs"`
}

var (
	ErrInvalidType = errors.New("invalid input type")
)
