package eth

import (
	"context"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathSign() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathSign(config.Chain.ETH),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: sign,
			},
		},
		HelpSynopsis:    "Sign a provided transaction object.",
		HelpDescription: `Sign a transaction`,
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
		// Если что‑то не передано или неправильно, возвращаем ошибку пользователю
		return nil, fmt.Errorf("invalid request data: %w", err)
	}

	keyManager, err := backend.GetKeyPairByAddressAndChain(ctx, req, name, address, config.Chain.ETH)
	if err != nil {
		return nil, fmt.Errorf("error retrieving signing keyManager %s", address)
	}

	privateKey, err := crypto.HexToECDSA(keyManager.PrivateKey)
	if err != nil {
		log.Error("Error converting hex to private key", "error", err)
		return nil, fmt.Errorf("error reconstructing private key from retrieved hex")
	}
	defer ZeroKey(privateKey)

	sig, err := crypto.Sign(common.HexToHash(hashInput).Bytes(), privateKey)
	if err != nil {
		log.Error("Error signing input hash", "error", err)
		return nil, fmt.Errorf("error reconstructing private key from retrieved hex")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": common.Bytes2Hex(sig),
		},
	}, nil
}
