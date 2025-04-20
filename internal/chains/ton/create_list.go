package ton

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/dsshard/vault-crypto-adapters/internal/types"
	"github.com/ethereum/go-ethereum/log"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathCreateAndList() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCreateListPattern(config.Chain.TON),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: tonCreateKeyManager,
			},
			logical.ListOperation: &framework.PathOperation{
				Callback: backend.WrapperListKeyManager(config.Chain.TON),
			},
		},
		HelpSynopsis:    backend.DefaultHelpHelpSynopsisCreateList,
		HelpDescription: backend.DefaultHelpDescriptionCreateList,
		Fields:          backend.DefaultCreateListManager,
	}
}

func tonCreateKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	// serviceName
	serviceName, ok := data.Get("service_name").(string)
	if !ok || serviceName == "" {
		return nil, fmt.Errorf("service_name must be a non-empty string")
	}
	// optional import
	privateKey, ok := data.Get("private_key").(string)
	if !ok {
		return nil, fmt.Errorf("private_key must be a hex string")
	}

	// retrieve or init KeyManager
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.TON, serviceName)
	if err != nil {
		return nil, err
	}
	if km == nil {
		km = &types.KeyManager{ServiceName: serviceName}
	}

	// generate or import ed25519 key
	var seed []byte
	if privateKey != "" {
		// strip optional 0x
		hexStr := strings.TrimPrefix(privateKey, "0x")
		bs, err := hex.DecodeString(hexStr)
		if err != nil || len(bs) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid private key")
		}
		seed = bs
	} else {
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, fmt.Errorf("failed to generate seed: %w", err)
		}
	}
	// derive key pair
	priv := ed25519.NewKeyFromSeed(seed)     // 64-byte private key
	pub := priv.Public().(ed25519.PublicKey) // 32-byte public key
	defer zeroSeed(seed)                     // wipe seed from memory

	// derive TON address (implement in utils.go)
	addr := DeriveAddress(pub)

	kp := &types.KeyPair{
		PrivateKey: hex.EncodeToString(seed),
		PublicKey:  hex.EncodeToString(pub),
		Address:    addr,
	}
	km.KeyPairs = append(km.KeyPairs, kp)

	// store back
	entry, _ := logical.StorageEntryJSON(
		fmt.Sprintf("key-managers/%s/%s", config.Chain.TON, serviceName),
		km,
	)
	if err := req.Storage.Put(ctx, entry); err != nil {
		log.Error("Failed to store key-manager", "error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": km.ServiceName,
			"address":      kp.Address,
			"public_key":   kp.PublicKey,
		},
	}, nil
}

// zeroSeed overwrites the seed bytes in memory.
func zeroSeed(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
