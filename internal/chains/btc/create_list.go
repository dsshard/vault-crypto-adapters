package btc

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/dsshard/vault-crypto-adapters/internal/types"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathCrud() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCrud(config.Chain.BTC),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: createKeyManager,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: backend.WrapperReadKeyManager(config.Chain.BTC),
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: backend.WrapperDeleteKeyManager(config.Chain.BTC),
			},
		},
		ExistenceCheck:  backend.KeyManagerExistenceCheck(config.Chain.BTC),
		HelpSynopsis:    backend.DefaultHelpHelpSynopsisCreateList,
		HelpDescription: backend.DefaultHelpDescriptionCreateList,
		Fields:          backend.DefaultCrudOperations,
	}
}

func createKeyManager(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	serviceName, ok := data.Get("name").(string)
	if !ok {
		return nil, errors.New("invalid input type")
	}
	privateKey := strings.TrimSpace(data.Get("private_key").(string))

	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.BTC, serviceName)
	if err != nil {
		return nil, err
	}
	if km == nil {
		km = &types.KeyManager{ServiceName: serviceName}
	}

	// Attempt to decode or generate the private key
	var privateKeyExport *btcec.PrivateKey
	if privateKey != "" {
		// 1) Попытка WIF
		if wif, err := btcutil.DecodeWIF(privateKey); err == nil {
			// WIF хранит уже сжатый ключ
			privateKeyExport, _ = btcec.PrivKeyFromBytes(wif.PrivKey.Serialize())
		} else if bts, err := hex.DecodeString(strings.TrimPrefix(privateKey, "0x")); err == nil && len(bts) == 32 {
			// 2) Попытка raw‑hex
			privateKeyExport, _ = btcec.PrivKeyFromBytes(bts)
		}
		// throw error
		if privateKeyExport == nil {
			return nil, fmt.Errorf("invalid private key")
		}
	}
	if privateKeyExport == nil {
		// 3) generate random
		privateKeyExport, _ = btcec.NewPrivateKey()
	}

	// Serialize private key + public key
	privateBytes := privateKeyExport.Serialize()
	pubBytes := privateKeyExport.PubKey().SerializeCompressed()

	// Generate P2PKH‑address
	address, err := DeriveAddress(privateKeyExport.PubKey())
	if err != nil {
		return nil, err
	}
	kp := &types.KeyPair{
		PrivateKey: hex.EncodeToString(privateBytes),
		PublicKey:  hex.EncodeToString(pubBytes),
		Address:    address,
	}
	km.KeyPairs = append(km.KeyPairs, kp)

	entry, _ := logical.StorageEntryJSON(fmt.Sprintf("key-managers/%s/%s", config.Chain.BTC, serviceName), km)
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": serviceName,
			"address":      kp.Address,
			"public_key":   kp.PublicKey,
		},
	}, nil
}
