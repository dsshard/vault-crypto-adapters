package sol

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	adaptersTypes "github.com/dsshard/vault-crypto-adapters/src/types"
	"github.com/portto/solana-go-sdk/common"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/portto/solana-go-sdk/types"
)

func PathCreateAndList() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCreateListPattern(config.Chain.SOL),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: createKeyManager},
			logical.ListOperation:   &framework.PathOperation{Callback: listKeyManagers},
		},
		HelpSynopsis:    "Create/import and list Solana key‑managers",
		HelpDescription: "POST serviceName + optional privateKey(base58 or hex) → pubkey, LIST → serviceNames",
		Fields: map[string]*framework.FieldSchema{
			"serviceName": {
				Type:        framework.TypeString,
				Description: "Identifier for this key‑manager",
			},
			"privateKey": {
				Type:        framework.TypeString,
				Description: "(Optional) base58 or hex‑encoded 64‑byte ed25519 seed. If omitted or invalid, a new keypair is generated.",
				Default:     "",
			},
		},
	}
}

// CreateKeyManagerSol handles POST /key-managers/sol
func createKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	svc := data.Get("serviceName").(string)
	if svc == "" {
		return nil, fmt.Errorf("serviceName is required")
	}
	inp := strings.TrimSpace(data.Get("privateKey").(string))

	// load or init
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.SOL, svc)
	if err != nil {
		return nil, err
	}
	if km == nil {
		km = &adaptersTypes.KeyManager{ServiceName: svc}
	}

	// decode or generate
	var acct types.Account
	if inp != "" {
		// try base58
		if a, err := types.AccountFromBase58(inp); err == nil {
			acct = a
		} else if bs, err := hex.DecodeString(strings.TrimPrefix(inp, "0x")); err == nil {
			acct, _ = types.AccountFromSeed(bs)
		}
	}
	if acct.PublicKey == (common.PublicKey{}) {
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

	storageKey := fmt.Sprintf("key-managers/%s/%s", config.Chain.SOL, svc)
	entry, _ := logical.StorageEntryJSON(storageKey, km)
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": svc,
			"address":      kp.Address,
			"public_key":   kp.PublicKey,
		},
	}, nil
}

func listKeyManagers(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, fmt.Sprintf("key-managers/%s/", config.Chain.SOL))
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}
