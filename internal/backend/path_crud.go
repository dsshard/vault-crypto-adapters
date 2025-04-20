package backend

import (
	"context"
	"errors"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/ethereum/go-ethereum/log"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func WrapperReadKeyManager(chain config.ChainType) func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		return readKeyManager(chain, ctx, req, data)
	}
}
func readKeyManager(
	chain config.ChainType,
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	serviceName, ok := data.Get("name").(string)
	if !ok {
		return nil, errors.New("invalid input type")
	}

	log.Info("Retrieving key manager for name", "name", serviceName)
	keyManager, err := RetrieveKeyManager(ctx, req, chain, serviceName)
	if err != nil {
		return nil, err
	}
	if keyManager == nil {
		return nil, fmt.Errorf("keyManager does not exist")
	}

	// Собираем пары address + public_key
	pairs := make([]map[string]string, len(keyManager.KeyPairs))
	for i, kp := range keyManager.KeyPairs {
		pairs[i] = map[string]string{
			"address":    kp.Address,
			"public_key": kp.PublicKey,
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": serviceName,
			"key_pairs":    pairs,
		},
	}, nil
}

func WrapperDeleteKeyManager(chain config.ChainType) func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		return deleteKeyManager(chain, ctx, req, data)
	}
}

func deleteKeyManager(
	chain config.ChainType,
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	serviceName, ok := data.Get("name").(string)
	if !ok {
		return nil, errors.New("invalid input type")
	}

	policy, err := RetrieveKeyManager(ctx, req, chain, serviceName)
	if err != nil {
		log.Error("Failed to retrieve the key-manager by name",
			"name", serviceName, "error", err)
		return nil, err
	}

	if policy == nil {
		return nil, nil
	}

	if err = req.Storage.Delete(ctx, fmt.Sprintf("key-managers/%s/%s", chain, policy.ServiceName)); err != nil {
		log.Error("Failed to delete the key-manager from storage",
			"service_name", serviceName, "error", err)
		return nil, err
	}
	return nil, nil
}
