// internal/usecase/sol/path_transfer_token.go

package sol

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"strconv"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/portto/solana-go-sdk/common"
	"github.com/portto/solana-go-sdk/program/tokenprog"
	"github.com/portto/solana-go-sdk/types"
)

func PathTransferToken() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathTransferToken(config.Chain.SOL),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: transferToken},
		},
		HelpSynopsis:    "Sign an SPL‑Token transfer for Solana",
		HelpDescription: "POST name, mint, to, amount, decimals, recentBlockhash",
		Fields: map[string]*framework.FieldSchema{
			"name":            {Type: framework.TypeString},
			"mint":            {Type: framework.TypeString, Description: "SPL token mint (base58)"},
			"to":              {Type: framework.TypeString, Description: "Recipient wallet (base58)"},
			"amount":          {Type: framework.TypeString, Description: "Raw token amount as decimal string"},
			"decimals":        {Type: framework.TypeString, Description: "Token decimals"},
			"recentBlockhash": {Type: framework.TypeString, Description: "Recent blockhash (base58)"},
		},
	}
}

func transferToken(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	// 1) Parse inputs
	svc := data.Get("name").(string)
	mintStr := data.Get("mint").(string)
	toStr := data.Get("to").(string)
	amountStr := data.Get("amount").(string)
	decimalsStr := data.Get("decimals").(string)
	blockhash := data.Get("recentBlockhash").(string)

	amount, err := strconv.ParseUint(amountStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %w", err)
	}
	dec, err := strconv.ParseUint(decimalsStr, 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid decimals: %w", err)
	}

	// 2) Load wallet from key‑manager
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.SOL, svc)
	if err != nil {
		return nil, err
	}
	if km == nil || len(km.KeyPairs) == 0 {
		return nil, fmt.Errorf("no key-manager for service %q", svc)
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

	// 3) Derive associated token accounts
	mint := common.PublicKeyFromString(mintStr)
	fromATA, _, err := common.FindAssociatedTokenAddress(acct.PublicKey, mint)
	if err != nil {
		return nil, fmt.Errorf("derive source ATA: %w", err)
	}
	toPub := common.PublicKeyFromString(toStr)
	toATA, _, err := common.FindAssociatedTokenAddress(toPub, mint)
	if err != nil {
		return nil, fmt.Errorf("derive dest ATA: %w", err)
	}

	// 4) Build the SPL transfer instruction
	instr := tokenprog.TransferChecked(tokenprog.TransferCheckedParam{
		From:     fromATA,
		To:       toATA,
		Mint:     mint,
		Auth:     acct.PublicKey,
		Signers:  nil,
		Amount:   amount,
		Decimals: uint8(dec),
	})

	// 5) Build and sign the transaction message
	msg := types.NewMessage(types.NewMessageParam{
		FeePayer:        acct.PublicKey,
		RecentBlockhash: blockhash,
		Instructions:    []types.Instruction{instr},
	})
	tx, err := types.NewTransaction(types.NewTransactionParam{
		Signers: []types.Account{acct},
		Message: msg,
	})
	if err != nil {
		return nil, fmt.Errorf("build tx: %w", err)
	}

	// 6) Serialize to raw bytes and encode as hex
	raw, err := tx.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize tx: %w", err)
	}
	rawHex := hex.EncodeToString(raw)

	return &logical.Response{
		Data: map[string]interface{}{
			"tx": rawHex,
		},
	}, nil
}
