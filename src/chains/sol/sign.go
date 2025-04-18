package sol

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/portto/solana-go-sdk/types"
)

// PathSignSol binds POST /key-managers/sol/{name}/sign
func PathSignSol() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathSign(config.Chain.SOL),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: sign},
		},
		HelpSynopsis:    "Sign an arbitrary hex message with Solana ED25519 key",
		HelpDescription: "POST name, message (hex string) → signature (hex)",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Key‑manager service name",
			},
			"message": {
				Type:        framework.TypeString,
				Description: "Hex‑encoded message to sign (e.g. transaction raw bytes)",
			},
		},
	}
}

// SignSol handles POST /key-managers/sol/{name}/sign
func sign(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	// 1) Parse inputs
	svc := data.Get("name").(string)
	msgHex, ok := data.Get("message").(string)
	if !ok {
		return nil, fmt.Errorf("invalid message")
	}
	msgHex = strings.TrimPrefix(msgHex, "0x")
	msgBytes, err := hex.DecodeString(msgHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex message: %w", err)
	}

	// 2) Load account from key‑manager
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.SOL, svc)
	if err != nil {
		return nil, err
	}
	if km == nil || len(km.KeyPairs) == 0 {
		return nil, fmt.Errorf("no key‑manager for service %q", svc)
	}

	rawPriv := km.KeyPairs[0].PrivateKey
	seed, err := hex.DecodeString(rawPriv)
	if err != nil {
		return nil, fmt.Errorf("invalid hex seed: %w", err)
	}
	acct, err := types.AccountFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("AccountFromSeed: %w", err)
	}

	// 3) Sign the message using ED25519
	sig := acct.Sign(msgBytes)
	// 4) Return hex‑encoded signature
	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hex.EncodeToString(sig),
		},
	}, nil
}
