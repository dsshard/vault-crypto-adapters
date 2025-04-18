package backend

import (
	"context"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/dsshard/vault-crypto-adapters/src/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type Backend struct{ *framework.Backend }

// PathExistenceCheck Data need for safe type
func PathExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		log.Error("existence check failed", "path", req.Path, "err", err)
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return entry != nil, nil
}

func RetrieveKeyManager(ctx context.Context, req *logical.Request, chain config.ChainType, service string) (*types.KeyManager, error) {
	path := fmt.Sprintf("key-managers/%s/%s", chain, service)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var km types.KeyManager
	if err := entry.DecodeJSON(&km); err != nil {
		return nil, err
	}
	return &km, nil
}
