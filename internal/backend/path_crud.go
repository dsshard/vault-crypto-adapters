package backend

import (
	"context"
	"errors"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/dsshard/vault-crypto-adapters/internal/types"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
)

func PathCrudList(chain config.ChainType) *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCrudList(chain),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: WrapperListKeyManager(chain),
			},
		},
		HelpSynopsis:    DefaultHelpHelpSynopsisCreateList,
		HelpDescription: DefaultHelpDescriptionCreateList,
		Fields:          DefaultListOperations,
	}
}

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

	log.Print("Retrieving key manager for name", serviceName)
	keyManager, err := RetrieveKeyManager(ctx, req, chain, serviceName)
	if err != nil {
		return nil, err
	}
	if keyManager == nil {
		return &logical.Response{
			Data: nil,
		}, nil
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
	// Validate inputs
	serviceName, ok := data.Get("name").(string)
	if !ok || serviceName == "" {
		return nil, errors.New("invalid input: name must be a non-empty string")
	}
	address, ok := data.Get("address").(string)
	if !ok || address == "" {
		return nil, errors.New("invalid input: address must be a non-empty string")
	}

	// Storage path for this service's path manager
	path := fmt.Sprintf("key-managers/%s/%s", chain, serviceName)

	// Fetch existing entry
	keyManager, err := RetrieveKeyManager(ctx, req, chain, serviceName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving signing keyManager %s", serviceName)
	}

	// Filter out the path pair matching the address
	filtered := make([]*types.KeyPair, 0, len(keyManager.KeyPairs))
	for _, kp := range keyManager.KeyPairs {
		if kp.Address != address {
			filtered = append(filtered, kp)
		}
	}

	// If no path pairs remain, delete the entire record
	if len(filtered) == 0 {
		if err := req.Storage.Delete(ctx, path); err != nil {
			return nil, fmt.Errorf("failed to delete path-manager: %w", err)
		}
	} else {
		keyManager.KeyPairs = filtered
		// Otherwise update with remaining path pairs
		entry, _ := logical.StorageEntryJSON(path, keyManager)
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}
	}

	return nil, nil
}

func WrapperListKeyManager(chain config.ChainType) func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		return listKeyManagers(chain, ctx, req)
	}
}

func listKeyManagers(
	chain config.ChainType,
	ctx context.Context,
	req *logical.Request,
) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, fmt.Sprintf("key-managers/%s/", chain))
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}
