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

func GetKeyPairByAddressAndChain(
	ctx context.Context,
	req *logical.Request,
	name string,
	address string,
	chain config.ChainType,
) (*types.KeyPair, error) {
	keyManager, err := RetrieveKeyManager(ctx, req, chain, name)
	if err != nil {
		return nil, fmt.Errorf("error retrieving signing keyManager %s", address)
	}

	if keyManager == nil {

		return nil, fmt.Errorf("signing keyManager %s does not exist", address)
	}

	if len(keyManager.KeyPairs) == 0 {
		return nil, fmt.Errorf("signing keyManager %s does not have a key pair", address)
	}

	var foundKeyPair *types.KeyPair
	for _, keyPairs := range keyManager.KeyPairs {
		if keyPairs.Address == address {
			foundKeyPair = keyPairs
			break
		}
	}

	if foundKeyPair == nil {
		return nil, fmt.Errorf("key pair not found for address %s", address)
	}

	if foundKeyPair.PrivateKey == "" {
		return nil, fmt.Errorf("private key not found for address %s", address)
	}

	return foundKeyPair, nil
}

func GetSignParamsFromData(data *framework.FieldData) (serviceName, hashInput, address string, err error) {
	// Извлекаем имя сервиса
	svcRaw := data.Get("name")
	svc, ok := svcRaw.(string)
	if !ok || svc == "" {
		err = fmt.Errorf("missing or invalid 'name' field: %v", svcRaw)
		return
	}

	// Извлекаем hash
	hRaw := data.Get("hash")
	h, ok := hRaw.(string)
	if !ok || h == "" {
		err = fmt.Errorf("missing or invalid 'hash' field: %v", hRaw)
		return
	}

	// Извлекаем address
	addrRaw := data.Get("address")
	addr, ok := addrRaw.(string)
	if !ok || addr == "" {
		err = fmt.Errorf("missing or invalid 'address' field: %v", addrRaw)
		return
	}

	serviceName = svc
	hashInput = h
	address = addr
	return
}
