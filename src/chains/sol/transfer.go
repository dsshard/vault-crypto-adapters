package sol

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/portto/solana-go-sdk/common"
	"github.com/portto/solana-go-sdk/program/sysprog"
	"github.com/portto/solana-go-sdk/types"
)

func PathTransferNativeSol() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathTransfer(config.Chain.SOL),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: transfer},
		},
		HelpSynopsis:    "Transfer native SOL on Solana",
		HelpDescription: "POST name, to, amount, recentBlockhash → tx (hex‑encoded signed transaction)",
		Fields: map[string]*framework.FieldSchema{
			"name":            {Type: framework.TypeString},
			"to":              {Type: framework.TypeString, Description: "Recipient wallet address (base58)"},
			"amount":          {Type: framework.TypeString, Description: "Amount of SOL in lamports (decimal string)"},
			"recentBlockhash": {Type: framework.TypeString, Description: "Recent blockhash (base58)"},
		},
	}
}

// TransferNativeSol handles POST /key-managers/sol/{name}/txn/sol/transfer
func transfer(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	// 1) Parse inputs
	svc := data.Get("name").(string)
	toStr := data.Get("to").(string)
	amtStr := data.Get("amount").(string)
	rawHash := data.Get("recentBlockhash").(string)

	amount, err := strconv.ParseUint(strings.TrimSpace(amtStr), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %w", err)
	}
	recentHash := strings.TrimSpace(rawHash)

	// 2) Load fee payer account
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.SOL, svc)
	if err != nil {
		return nil, err
	}
	if km == nil || len(km.KeyPairs) == 0 {
		return nil, fmt.Errorf("no key‑manager for service %q", svc)
	}
	rawPriv := km.KeyPairs[0].PrivateKey
	seed, err := hex.DecodeString(rawPriv)
	if err != nil {
		return nil, fmt.Errorf("invalid hex seed: %w", err)
	}
	acct, err := types.AccountFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("AccountFromSeed: %w", err)
	}

	// 3) Build transfer instruction
	toPub := common.PublicKeyFromString(toStr)
	instr := sysprog.Transfer(sysprog.TransferParam{
		From:   acct.PublicKey,
		To:     toPub,
		Amount: amount,
	}) // :contentReference[oaicite:0]{index=0}

	// 4) Build & sign transaction
	msg := types.NewMessage(types.NewMessageParam{
		FeePayer:        acct.PublicKey,
		RecentBlockhash: recentHash,
		Instructions:    []types.Instruction{instr},
	})
	tx, err := types.NewTransaction(types.NewTransactionParam{
		Signers: []types.Account{acct},
		Message: msg,
	})
	if err != nil {
		return nil, fmt.Errorf("build transaction: %w", err)
	}

	// 5) Serialize & return hex
	raw, err := tx.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize transaction: %w", err)
	}
	hexTx := hex.EncodeToString(raw)

	return &logical.Response{
		Data: map[string]interface{}{
			"tx": hexTx,
		},
	}, nil
}
