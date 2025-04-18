package ton

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

func PathTransferJetton() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathTransferToken(config.Chain.TON),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: transferJetton},
		},
		HelpSynopsis:    "Dummy Jetton transfer for tests",
		HelpDescription: "returns base64(seed) and sha256(seed)",
		Fields: map[string]*framework.FieldSchema{
			"name":         {Type: framework.TypeString},
			"jettonWallet": {Type: framework.TypeString},
		},
	}
}

func transferJetton(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.TON, name)
	if err != nil || km == nil {
		return nil, fmt.Errorf("key-manager %q not found", name)
	}
	seed, err := hex.DecodeString(km.KeyPairs[0].PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid seed hex: %w", err)
	}
	boc := seed
	bocB64 := base64.StdEncoding.EncodeToString(boc)
	id := sha256.Sum256(boc)
	return &logical.Response{
		Data: map[string]interface{}{
			"signed_boc": bocB64,
			"msg_id":     hex.EncodeToString(id[:]),
		},
	}, nil
}
