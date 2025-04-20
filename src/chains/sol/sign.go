package sol

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/ethereum/go-ethereum/log"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/portto/solana-go-sdk/types"
)

func PathSignSol() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathSign(config.Chain.SOL),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: sign},
		},
		HelpSynopsis:    "Sign an arbitrary hex message with Solana ED25519 key",
		HelpDescription: "POST name, message (hex string) → signature (hex)",
		Fields:          backend.DefaultSignOperation,
	}
}

func sign(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, hashInput, address, err := backend.GetSignParamsFromData(data)
	if err != nil {
		return nil, fmt.Errorf("invalid request data: %w", err)
	}

	hashInput = strings.TrimPrefix(hashInput, "0x")
	msgBytes, err := hex.DecodeString(hashInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex message: %w", err)
	}

	// 2) Load account from key‑manager
	keyManager, err := backend.GetKeyPairByAddressAndChain(ctx, req, name, address, config.Chain.SOL)
	if err != nil {
		log.Error("Failed to retrieve the signing keyManager",
			"address", address, "error", err)
		return nil, fmt.Errorf("error retrieving signing keyManager %s", address)
	}

	seed, err := hex.DecodeString(keyManager.PrivateKey)
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
