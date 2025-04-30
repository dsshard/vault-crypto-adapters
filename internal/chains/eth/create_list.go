package eth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/dsshard/vault-crypto-adapters/internal/types"
	"github.com/ethereum/go-ethereum/log"
	"regexp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathCrud() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCrud(config.Chain.ETH),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: createKeyManager,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: backend.WrapperReadKeyManager(config.Chain.ETH),
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: backend.WrapperDeleteKeyManager(config.Chain.ETH),
			},
		},
		ExistenceCheck:  backend.KeyManagerExistenceCheck(config.Chain.ETH),
		HelpSynopsis:    backend.DefaultHelpHelpSynopsisCreateList,
		HelpDescription: backend.DefaultHelpDescriptionCreateList,
		Fields:          backend.DefaultCrudOperations,
	}
}

func createKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	serviceName, ok := data.Get("name").(string)
	if !ok {
		return nil, errors.New("invalid input type")
	}

	privateKey, ok := data.Get("private_key").(string)
	if !ok {
		return nil, types.ErrInvalidType
	}

	keyManager, err := backend.RetrieveKeyManager(ctx, req, config.Chain.ETH, serviceName)
	if err != nil {
		return nil, err
	}

	if keyManager == nil {
		keyManager = &types.KeyManager{
			ServiceName: serviceName,
		}
	}

	var privateKeyExport *ecdsa.PrivateKey
	var privateKeyBytes []byte

	if privateKey != "" {
		re := regexp.MustCompile("[0-9a-fA-F]{64}$")

		key := re.FindString(privateKey)
		if key == "" {
			return nil, fmt.Errorf("invalid private key")
		}

		privateKeyExport, err = crypto.HexToECDSA(key)
		if err != nil {
			return nil, fmt.Errorf("error reconstructing private key from input hex, %w", err)
		}
		if privateKeyExport == nil {
			return nil, fmt.Errorf("invalid private key")
		}
	} else {
		privateKeyExport, _ = crypto.GenerateKey()
	}

	privateKeyBytes = crypto.FromECDSA(privateKeyExport)
	defer ZeroKey(privateKeyExport)

	publicKey := privateKeyExport.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	keyPair := &types.KeyPair{
		PrivateKey: common.Bytes2Hex(privateKeyBytes),
		PublicKey:  common.Bytes2Hex(publicKeyBytes),
		Address:    crypto.PubkeyToAddress(*publicKeyECDSA).Hex(),
	}

	keyManager.KeyPairs = append(keyManager.KeyPairs, keyPair)

	entry, _ := logical.StorageEntryJSON(config.GetStoragePath(config.Chain.ETH, serviceName), keyManager)
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		log.Error("Failed to save the new keyManager to storage", "error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": keyManager.ServiceName,
			"address":      keyPair.Address,
			"public_key":   keyPair.PublicKey,
		},
	}, nil
}
