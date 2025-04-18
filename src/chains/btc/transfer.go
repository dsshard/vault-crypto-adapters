package btc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathTransfer() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathTransfer(config.Chain.BTC),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: transfer},
		},
		HelpSynopsis:    "Dummy BTC transfer for tests",
		HelpDescription: "↪ returns base64(privkey) and sha256(privkey).",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
		},
	}
}

func transfer(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	svc := data.Get("name").(string)
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.BTC, svc)
	if err != nil || km == nil {
		return nil, fmt.Errorf("not found")
	}
	priv, _ := hex.DecodeString(km.KeyPairs[0].PrivateKey)
	b64 := base64.StdEncoding.EncodeToString(priv)
	sum := sha256.Sum256(priv)
	return &logical.Response{Data: map[string]interface{}{
		"signed_tx": b64,
		"txid":      hex.EncodeToString(sum[:]),
	}}, nil
}
