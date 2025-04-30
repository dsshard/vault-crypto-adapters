package doge

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/dsshard/vault-crypto-adapters/internal/types"
)

// PathCrud registers CRUD operations for Dogecoin key-managers
func PathCrud() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCrud(config.Chain.DOGE),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: createKeyManager,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: backend.WrapperReadKeyManager(config.Chain.DOGE),
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: backend.WrapperDeleteKeyManager(config.Chain.DOGE),
			},
		},
		ExistenceCheck:  backend.KeyManagerExistenceCheck(config.Chain.DOGE),
		HelpSynopsis:    backend.DefaultHelpHelpSynopsisCreateList,
		HelpDescription: backend.DefaultHelpDescriptionCreateList,
		Fields:          backend.DefaultCrudOperations,
	}
}

// createKeyManager handles POST /key-managers/doge
func createKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	// service name
	serviceName, ok := data.Get("name").(string)
	if !ok || serviceName == "" {
		return nil, fmt.Errorf("name is required")
	}
	// optional private key: WIF or hex
	privInput, ok := data.Get("private_key").(string)
	if !ok {
		return nil, fmt.Errorf("private_key must be a string")
	}
	privInput = strings.TrimSpace(privInput)

	// retrieve or init key-manager
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.DOGE, serviceName)
	if err != nil {
		return nil, err
	}
	if km == nil {
		km = &types.KeyManager{ServiceName: serviceName}
	}

	// decode or generate private key
	var privKey *btcec.PrivateKey
	if privInput != "" {
		// try WIF
		if wif, err := btcutil.DecodeWIF(privInput); err == nil {
			privKey = wif.PrivKey
		} else if bs, err := hex.DecodeString(strings.TrimPrefix(privInput, "0x")); err == nil && len(bs) == 32 {
			// raw hex seed
			privKey, _ = btcec.PrivKeyFromBytes(bs)
		}
		if privKey == nil {
			return nil, fmt.Errorf("invalid private key")
		}
	} else {
		// new random key
		privKey, _ = btcec.NewPrivateKey()
	}

	// derive public key and address
	pubKey := privKey.PubKey()
	address, err := DeriveAddress(pubKey)
	if err != nil {
		return nil, err
	}

	// store key-pair
	kp := &types.KeyPair{
		PrivateKey: hex.EncodeToString(privKey.Serialize()),
		PublicKey:  hex.EncodeToString(pubKey.SerializeCompressed()),
		Address:    address,
	}
	km.KeyPairs = append(km.KeyPairs, kp)

	// persist
	entry, _ := logical.StorageEntryJSON(config.GetStoragePath(config.Chain.DOGE, serviceName), km)
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// response
	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": serviceName,
			"address":      address,
			"public_key":   kp.PublicKey,
		},
	}, nil
}
