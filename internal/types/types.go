package types

import (
	"errors"
	"github.com/hashicorp/vault/sdk/framework"
)

type KeyPair struct {
	PrivateKey         string                 `json:"private_key"`
	PublicKey          string                 `json:"public_key"`
	Address            string                 `json:"address"`
	ExternalData       map[string]interface{} `json:"external_data,omitempty"`
	IsLockExternalData bool                   `json:"is_lock_external_data,omitempty"`
}

type KeyManager struct {
	ServiceName string     `json:"service_name"`
	KeyPairs    []*KeyPair `json:"key_pairs"`
}

var (
	ErrInvalidType = errors.New("invalid input type")
)

type ResponseDataCreateList struct {
	*framework.FieldData
	ServiceName string `json:"service_name"`
	Address     string `json:"address"`
	PublicKey   string `json:"public_key"`
}
