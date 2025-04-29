package xrp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/dsshard/vault-crypto-adapters/internal/types"
)

func PathCrud() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCrud(config.Chain.XRP),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: createKeyManager,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: backend.WrapperReadKeyManager(config.Chain.XRP),
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: backend.WrapperDeleteKeyManager(config.Chain.XRP),
			},
		},
		ExistenceCheck:  backend.KeyManagerExistenceCheck(config.Chain.XRP),
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
	// 1) Inputs
	serviceName, ok := data.Get("name").(string)
	if !ok {
		return nil, errors.New("invalid input type")
	}
	privHex, ok := data.Get("private_key").(string)
	if !ok {
		return nil, fmt.Errorf("private_key must be a string")
	}
	privHex = strings.TrimSpace(privHex)

	// 2) Retrieve or init KeyManager
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.XRP, serviceName)
	if err != nil {
		return nil, err
	}
	if km == nil {
		km = &types.KeyManager{ServiceName: serviceName}
	}

	// 3) Decode or generate 32‑byte seed
	var seed [32]byte
	if privHex != "" {
		bs, err := hex.DecodeString(strings.TrimPrefix(privHex, "0x"))
		if err != nil || len(bs) != len(seed) {
			return nil, fmt.Errorf("invalid private key")
		}
		copy(seed[:], bs)
	} else {
		if _, err := rand.Read(seed[:]); err != nil {
			return nil, fmt.Errorf("failed to generate seed: %w", err)
		}
	}
	defer zeroSeed(seed[:])

	// 4) Build secp256k1 keypair
	priv, _ := btcec.PrivKeyFromBytes(seed[:])
	pub := priv.PubKey()

	// 5) Derive XRP‑address
	addr := DeriveClassicXRPAddress(pub.SerializeCompressed())

	// 6) Save KeyPair
	kp := &types.KeyPair{
		PrivateKey: hex.EncodeToString(seed[:]),
		PublicKey:  hex.EncodeToString(pub.SerializeCompressed()),
		Address:    addr,
	}
	km.KeyPairs = append(km.KeyPairs, kp)

	// 7) Persist
	path := fmt.Sprintf("key-managers/%s/%s", config.Chain.XRP, serviceName)
	entry, _ := logical.StorageEntryJSON(path, km)
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// 8) Response
	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": serviceName,
			"address":      addr,
			"public_key":   kp.PublicKey,
		},
	}, nil
}

// zeroSeed обнуляет срез байт seed.
func zeroSeed(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
