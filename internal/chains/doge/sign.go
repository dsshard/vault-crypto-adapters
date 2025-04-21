package doge

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathSign() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathSign(config.Chain.DOGE),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: signHash},
		},
		HelpSynopsis:    "Sign a 32‑byte hash",
		HelpDescription: "POST name, hash(hex) → signature(hex).",
		Fields:          backend.DefaultSignOperation,
	}
}

func signHash(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// Extract service name, hex‑encoded hash and address from the request
	name, hashHex, address, err := backend.GetSignParamsFromData(data)
	if err != nil {
		return nil, fmt.Errorf("invalid request data: %w", err)
	}

	// Lookup the KeyPair by address under the DOGE chain
	kp, err := backend.GetKeyPairByAddressAndChain(ctx, req, name, address, config.Chain.DOGE)
	if err != nil {
		return nil, fmt.Errorf("error retrieving signing key for address %s: %w", address, err)
	}

	// Decode and validate the 32‑byte hash
	hash, err := hex.DecodeString(hashHex)
	if err != nil || len(hash) != 32 {
		return nil, fmt.Errorf("invalid hash: must be 32 bytes hex")
	}

	// Rebuild the private key
	privBytes, err := hex.DecodeString(kp.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("stored private key is not valid hex: %w", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)

	// Sign the hash using ECDSA (secp256k1)
	sig := ecdsa.Sign(priv, hash)

	// Serialize to DER and hex‑encode
	sigBytes := sig.Serialize()
	sigHex := hex.EncodeToString(sigBytes)

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": sigHex,
		},
	}, nil
}
