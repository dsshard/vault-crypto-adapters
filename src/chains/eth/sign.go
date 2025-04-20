package eth

import (
	"context"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
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
		HelpSynopsis: "Sign a provided transaction object.",
		HelpDescription: `

    Sign a transaction object with properties conforming to the Ethereum JSON-RPC documentation.

    `,
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
