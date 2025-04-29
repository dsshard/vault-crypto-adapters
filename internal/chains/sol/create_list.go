package sol

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	adaptersTypes "github.com/dsshard/vault-crypto-adapters/internal/types"
	"github.com/mr-tron/base58"

	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/portto/solana-go-sdk/types"
)

func PathCrud() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCrud(config.Chain.SOL),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: createKeyManager,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: backend.WrapperReadKeyManager(config.Chain.SOL),
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: backend.WrapperDeleteKeyManager(config.Chain.SOL),
			},
		},
		ExistenceCheck:  backend.KeyManagerExistenceCheck(config.Chain.SOL),
		HelpSynopsis:    backend.DefaultHelpHelpSynopsisCreateList,
		HelpDescription: backend.DefaultHelpDescriptionCreateList,
		Fields:          backend.DefaultCrudOperations,
	}
}

// CreateKeyManagerSol handles POST /key-managers/sol
func createKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	serviceName, ok := data.Get("name").(string)
	if !ok {
		return nil, errors.New("invalid input type")
	}
	privateKey := strings.TrimSpace(data.Get("private_key").(string))

	// load or init
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.SOL, serviceName)
	if err != nil {
		return nil, err
	}
	if km == nil {
		km = &adaptersTypes.KeyManager{ServiceName: serviceName}
	}

	// decode or generate
	var acct types.Account
	if privateKey != "" {
		// 1) Try hex‐encoded 32‐byte seed
		hexSeed := strings.TrimPrefix(privateKey, "0x")
		bs, errHex := hex.DecodeString(hexSeed)
		if errHex == nil && len(bs) == ed25519.SeedSize {
			// valid 32‐byte seed
			acct, err = types.AccountFromSeed(bs)
			if err != nil {
				return nil, fmt.Errorf("invalid private key (seed): %w", err)
			}
		} else {
			// 2) Fallback: try Base58 secret key (64 bytes)
			decoded, errB58 := base58.Decode(privateKey)
			if errB58 != nil || len(decoded) != ed25519.PrivateKeySize {
				return nil, fmt.Errorf("invalid private key: neither valid 32‑byte hex seed nor 64‑byte base58 secret")
			}
			acct, err = types.AccountFromBase58(privateKey)
			if err != nil {
				return nil, fmt.Errorf("invalid private key (base58): %w", err)
			}
		}
	} else {
		// no privateKey → generate new random keypair
		acct = types.NewAccount()
	}

	// берём первые 32 байта seed — именно то, что любит AccountFromSeed
	seed := acct.PrivateKey[:32]
	kp := &adaptersTypes.KeyPair{
		PrivateKey: hex.EncodeToString(seed), // base58
		PublicKey:  acct.PublicKey.String(),
		Address:    acct.PublicKey.String(),
	}
	km.KeyPairs = append(km.KeyPairs, kp)

	storageKey := fmt.Sprintf("key-managers/%s/%s", config.Chain.SOL, serviceName)
	entry, _ := logical.StorageEntryJSON(storageKey, km)
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": serviceName,
			"address":      kp.Address,
			"public_key":   kp.PublicKey,
		},
	}, nil
}
