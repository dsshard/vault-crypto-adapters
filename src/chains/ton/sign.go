package ton

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathSign() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathSign(config.Chain.TON),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: signHash,
			},
		},
		HelpSynopsis:    "Sign a 32‑byte SHA256 hash with a TON Ed25519 key.",
		HelpDescription: "POST name, hash(hex‑encoded SHA256) → signature(hex‑encoded Ed25519).",
		Fields: map[string]*framework.FieldSchema{
			"name": {Type: framework.TypeString},
			"hash": {
				Type:        framework.TypeString,
				Description: "Hex‑encoded 32‑byte SHA256 hash to sign.",
			},
		},
	}
}

func signHash(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name := data.Get("name").(string)
	hashHex := data.Get("hash").(string)

	// 1) Load KeyManager and seed
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.TON, name)
	if err != nil || km == nil {
		return nil, fmt.Errorf("key-manager %q not found", name)
	}
	seed, err := hex.DecodeString(km.KeyPairs[0].PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid stored seed hex: %w", err)
	}
	// derive full private key
	priv := ed25519.NewKeyFromSeed(seed)
	defer zeroSeed(seed) // wipe seed

	// 2) Decode the hash
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex: %w", err)
	}
	if len(hashBytes) != 32 {
		return nil, fmt.Errorf("hash must be 32 bytes, got %d", len(hashBytes))
	}

	// 3) Sign
	sig := ed25519.Sign(priv, hashBytes)

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hex.EncodeToString(sig),
		},
	}, nil
}
