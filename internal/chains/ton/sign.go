package ton

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathSign() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathSign(config.Chain.TON),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: signHash,
			},
		},
		HelpSynopsis:    "Sign a 32‑byte SHA256 hash with a TON Ed25519 key.",
		HelpDescription: "POST name, hash(hex‑encoded SHA256) → signature(hex‑encoded Ed25519).",
		Fields:          backend.DefaultSignOperation,
	}
}

func signHash(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, hashInput, address, err := backend.GetSignParamsFromData(data)
	if err != nil {
		return nil, fmt.Errorf("invalid request data: %w", err)
	}

	// 2) Load account from key‑manager
	keyManager, err := backend.GetKeyPairByAddressAndChain(ctx, req, name, address, config.Chain.TON)
	if err != nil {
		return nil, fmt.Errorf("error retrieving signing keyManager %s", address)
	}

	seed, err := hex.DecodeString(keyManager.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid stored seed hex: %w", err)
	}
	// derive full private key
	priv := ed25519.NewKeyFromSeed(seed)
	defer zeroSeed(seed) // wipe seed

	// 2) Decode the hash
	hashBytes, err := hex.DecodeString(hashInput)
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex: %w", err)
	}
	sig := ed25519.Sign(priv, hashBytes)

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hex.EncodeToString(sig),
		},
	}, nil
}
