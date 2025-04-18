package eth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/dsshard/vault-crypto-adapters/src/types"
	"github.com/ethereum/go-ethereum/log"
	"regexp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathCreateAndList() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCreateListPattern(config.Chain.ETH),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: createKeyManager,
			},
			logical.ListOperation: &framework.PathOperation{
				Callback: listKeyManagers,
			},
		},
		HelpSynopsis: "Create new key-manager with input private-key or random private-key & list all the key-managers maintained by the plugin backend.",
		HelpDescription: `

    POST - create a new keyManager
    LIST - list all keyManagers

    `,
		Fields: map[string]*framework.FieldSchema{
			"serviceName": {
				Type:        framework.TypeString,
				Description: "The service that is the owner of the private-key",
				Default:     "",
			},
			"privateKey": {
				Type:        framework.TypeString,
				Description: "(Optional, default random key) Hex string for the private key (32-byte or 64-char long). If present, the request will import the given key instead of generating a new key.",
				Default:     "",
			},
		},
	}
}

func listKeyManagers(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, fmt.Sprintf("key-managers/%s/", config.Chain.ETH))
	if err != nil {
		log.Error("Failed to retrieve the list of keyManagers", "error", err)
		return nil, err
	}

	return logical.ListResponse(vals), nil
}

func createKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	serviceInput, ok := data.Get("serviceName").(string)
	if !ok {
		return nil, errInvalidType
	}

	keyInput, ok := data.Get("privateKey").(string)
	if !ok {
		return nil, errInvalidType
	}

	keyManager, err := backend.RetrieveKeyManager(ctx, req, config.Chain.ETH, serviceInput)
	if err != nil {
		return nil, err
	}

	if keyManager == nil {
		keyManager = &types.KeyManager{
			ServiceName: serviceInput,
		}
	}

	var privateKey *ecdsa.PrivateKey
	var privateKeyBytes []byte

	if keyInput != "" {
		re := regexp.MustCompile("[0-9a-fA-F]{64}$")

		key := re.FindString(keyInput)
		if key == "" {
			log.Error("Input private key did not parse successfully", "privateKey", keyInput)
			return nil, fmt.Errorf("privateKey must be a 32-byte hexidecimal string")
		}

		privateKey, err = crypto.HexToECDSA(key)
		if err != nil {
			log.Error("Error reconstructing private key from input hex", "error", err)
			return nil, fmt.Errorf("error reconstructing private key from input hex, %w", err)
		}
	} else {
		privateKey, _ = crypto.GenerateKey()
	}

	privateKeyBytes = crypto.FromECDSA(privateKey)
	defer ZeroKey(privateKey)

	publicKey := privateKey.Public()
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

	policyPath := fmt.Sprintf("key-managers/%s/%s", config.Chain.ETH, serviceInput)
	entry, _ := logical.StorageEntryJSON(policyPath, keyManager)
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
