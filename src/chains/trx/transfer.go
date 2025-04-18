package trx

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func PathTransferTx() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathTransfer(config.Chain.TRX),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: transfer,
			},
		},
		HelpSynopsis:    "Build & sign a TRON transfer transaction.",
		HelpDescription: "POST name, to, amount (SUN), feeLimit (optional) → signed_tx (base64 protobuf), tx_id (hex).",
		Fields: map[string]*framework.FieldSchema{
			"name":     {Type: framework.TypeString},
			"to":       {Type: framework.TypeString},
			"amount":   {Type: framework.TypeString},
			"feeLimit": {Type: framework.TypeInt, Default: 10000000},
		},
	}
}

func transfer(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	toStr := data.Get("to").(string)
	amtStr := data.Get("amount").(string)
	feeLimit := data.Get("feeLimit").(int)

	// 1) Получаем приватный ключ
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.TRX, name)
	if err != nil || km == nil {
		return nil, fmt.Errorf("key-manager %s not found", name)
	}
	privHex := km.KeyPairs[0].PrivateKey
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)
	defer ZeroKey(privKey.ToECDSA())

	// 2) Decode addresses and amount
	ownerAddr := DecodeBase58(name)
	toAddr := DecodeBase58(toStr)
	amount, err := strconv.ParseInt(amtStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount: %w", err)
	}

	// 3) Build TransferContract
	contract := &core.TransferContract{
		OwnerAddress: ownerAddr,
		ToAddress:    toAddr,
		Amount:       amount,
	}
	paramAny, err := anypb.New(contract)

	if err != nil {
		return nil, fmt.Errorf("marshal contract: %w", err)
	}

	raw := &core.TransactionRaw{
		Contract: []*core.Transaction_Contract{{
			Type:      core.Transaction_Contract_TransferContract,
			Parameter: paramAny,
		}},
		Timestamp:  time.Now().UnixNano() / 1e6,
		Expiration: time.Now().Add(10*time.Minute).UnixNano() / 1e6,
		FeeLimit:   int64(feeLimit),
	}
	tx := &core.Transaction{RawData: raw}

	// 4) Sign rawData
	rawBytes, err := proto.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal rawData: %w", err)
	}
	hash := sha256.Sum256(rawBytes)
	sig, err := crypto.Sign(hash[:], privKey.ToECDSA())
	if err != nil {
		return nil, fmt.Errorf("sign failed: %w", err)
	}
	tx.Signature = append(tx.Signature, sig)

	// 5) Serialize full TX and compute tx_id
	fullTx, err := proto.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("marshal full tx: %w", err)
	}
	b64 := base64.StdEncoding.EncodeToString(fullTx)
	txID := sha256.Sum256(rawBytes) // or compute differently via node

	return &logical.Response{
		Data: map[string]interface{}{
			"signed_tx": b64,
			"tx_id":     hex.EncodeToString(txID[:]),
		},
	}, nil
}
