package trx

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathSign() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathSign(config.Chain.TRX),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: sign,
			},
		},
		HelpSynopsis:    "Sign a SHA256 hash for TRON transaction.",
		HelpDescription: "POST name & hash (hex SHA256 rawData) → signature (hex r||s||v).",
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

	// 2) Load account from key‑manager
	keyManager, err := backend.GetKeyPairByAddressAndChain(ctx, req, name, address, config.Chain.TRX)
	if err != nil {
		return nil, fmt.Errorf("error retrieving signing keyManager %s", address)
	}
	privateKeyHex := keyManager.PrivateKey

	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	defer ZeroKey(privateKey)

	// 3) Декодируем SHA256‑хеш (hex)
	hashBytes, err := hex.DecodeString(hashInput)
	if err != nil {
		return nil, fmt.Errorf("invalid hash hex: %w", err)
	}

	// 4) Подписываем через go-ethereum crypto.Sign (r||s||v, 65 байт)
	sigBytes, err := crypto.Sign(hashBytes, privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign failed: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hex.EncodeToString(sigBytes),
		},
	}, nil
}
