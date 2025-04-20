package backend

import (
	"context"
	"errors"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/ethereum/go-ethereum/log"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathReadAndDelete(chain config.ChainType) *framework.Path {
	return &framework.Path{
		Pattern:      config.CreatePathReadAndDelete(chain),
		HelpSynopsis: "Create, get or delete a policy by name",
		HelpDescription: `
    GET - return the key-manager by the name
    DELETE - deletes the key-manager by the name
    `,
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
		},
		ExistenceCheck: PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: wrapperReadKeyManager(chain),
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: wrapperDeleteKeyManager(chain),
			},
		},
	}
}

func wrapperReadKeyManager(chain config.ChainType) func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	addresses := make([]string, len(keyManager.KeyPairs))
	for i := range keyManager.KeyPairs {
		addresses[i] = keyManager.KeyPairs[i].Address
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": keyManager.ServiceName,
			"addresses":    addresses,
		},
	}, nil
}

func wrapperDeleteKeyManager(chain config.ChainType) func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

func WrapperListKeyManager(chain config.ChainType) func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		return listKeyManagers(chain, ctx, req, data)
	}
}

func listKeyManagers(
	chain config.ChainType,
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, fmt.Sprintf("key-managers/%s/", chain))
	if err != nil {
		log.Error("Failed to list key-managers", "error", err)
		return nil, err
	}
	return logical.ListResponse(names), nil
}
