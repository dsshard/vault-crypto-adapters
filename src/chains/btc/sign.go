package btc

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathSign() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathSign(config.Chain.BTC),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: signHash},
		},
		HelpSynopsis:    "Sign a 32‑byte hash with secp256k1 (schnorr)",
		HelpDescription: "POST name, hash(hex) → signature(hex).",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
			"hash": {
				Type:        framework.TypeString,
				Description: "Hex string of the hash that should be signed.",
				Default:     "",
			},
			"address": {
				Type:        framework.TypeString,
				Description: "The address that belongs to a private key in the key-manager.",
			},
		},
	}
}

func signHash(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name, hashInput, address, err := backend.GetSignParamsFromData(data)

	keyManager, err := backend.GetKeyPairByAddressAndChain(ctx, req, name, address, config.Chain.BTC)
	if err != nil {
		return nil, fmt.Errorf("error retrieving signing keyManager %s", address)
	}

	hash, err := hex.DecodeString(hashInput)
	if err != nil || len(hash) != 32 {
		return nil, fmt.Errorf("invalid hash")
	}
	privBytes, _ := hex.DecodeString(keyManager.PrivateKey)
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	sig, err := schnorr.Sign(priv, hash)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]interface{}{
		"signature": hex.EncodeToString(sig.Serialize()),
	}}, nil
}
