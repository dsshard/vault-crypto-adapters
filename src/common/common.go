package common

import (
	"context"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/chains"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() *backend.Backend {
	b := &backend.Backend{}
	b.Backend = &framework.Backend{
		Help:  "Vault Bitcoin Signer plugin: key‑managers, sign, build dummy tx",
		Paths: framework.PathAppend(chains.Paths()),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"key-managers/"},
		},
		BackendType: logical.TypeLogical,
	}
	return b
}
