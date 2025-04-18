package btc

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/dsshard/vault-crypto-adapters/src/types"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathCreateAndList() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCreateListPattern(config.Chain.BTC),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: createKeyManager},
			logical.ListOperation:   &framework.PathOperation{Callback: listKeyManagers},
		},
		HelpSynopsis:    "Create/import and list Bitcoin key‑managers",
		HelpDescription: "POST serviceName + optional privateKey(hex) → pub/address, LIST → all services",
		Fields: map[string]*framework.FieldSchema{
			"serviceName": {
				Type:        framework.TypeString,
				Description: "Your service identifier",
			},
			"privateKey": {
				Type:        framework.TypeString,
				Description: "(Optional) 64‑hex chars secp256k1 privkey. If omitted or invalid, new random key is generated.",
				Default:     "",
			},
		},
	}
}

func listKeyManagers(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, fmt.Sprintf("key-managers/%s/", config.Chain.BTC))
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}

func createKeyManager(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	svc, _ := data.Get("serviceName").(string)
	privInput := strings.TrimSpace(data.Get("privateKey").(string))

	if svc == "" {
		return nil, fmt.Errorf("serviceName must be set")
	}

	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.BTC, svc)
	if err != nil {
		return nil, err
	}
	if km == nil {
		km = &types.KeyManager{ServiceName: svc}
	}

	// Попытка распарсить пользовательский privkey, иначе – генерим новый
	var privKey *btcec.PrivateKey
	if privInput != "" {
		// 1) Попытка WIF
		if wif, err := btcutil.DecodeWIF(privInput); err == nil {
			// WIF хранит уже сжатый ключ
			privKey, _ = btcec.PrivKeyFromBytes(wif.PrivKey.Serialize())
		} else if bts, err := hex.DecodeString(strings.TrimPrefix(privInput, "0x")); err == nil && len(bts) == 32 {
			// 2) Попытка raw‑hex
			privKey, _ = btcec.PrivKeyFromBytes(bts)
		}
		// throw error
		if privKey == nil {
			return nil, fmt.Errorf("invalid private key")
		}
	}
	if privKey == nil {
		// 3) Генерируем случайный
		privKey, _ = btcec.NewPrivateKey()
	}

	// Серилизуем приват + публичный ключ
	privBytes := privKey.Serialize()
	pubBytes := privKey.PubKey().SerializeCompressed()

	// Генерируем P2PKH‑адрес вручную
	address, err := DeriveAddress(privKey.PubKey())
	if err != nil {
		return nil, err
	}
	kp := &types.KeyPair{
		PrivateKey: hex.EncodeToString(privBytes),
		PublicKey:  hex.EncodeToString(pubBytes),
		Address:    address,
	}
	km.KeyPairs = append(km.KeyPairs, kp)

	entry, _ := logical.StorageEntryJSON(fmt.Sprintf("key-managers/%s/%s", config.Chain.BTC, svc), km)
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": svc,
			"address":      kp.Address,
			"public_key":   kp.PublicKey,
		},
	}, nil
}
