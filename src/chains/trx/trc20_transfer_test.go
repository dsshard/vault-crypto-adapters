package trx_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"github.com/dsshard/vault-crypto-adapters/src/chains/trx"
	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"testing"
)

func TestTrxTransferTRC20(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// Create key‐manager
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/trx")
	req.Storage = storage
	req.Data = map[string]interface{}{"serviceName": "svc"}
	_, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)

	// Read address
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/trx/svc")
	req.Storage = storage
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	addrs := resp.Data["addresses"].([]string)
	assert.Len(t, addrs, 1)
	owner := addrs[0]

	// For TRC20 transfer we need to set contract address
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/trx/svc/transfer/token")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"name":     "svc",
		"contract": owner, // instead of token address we use owner address
		"to":       owner, // send to self
		"amount":   "1234",
		"feeLimit": 2000000,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)

	// Unpack signed_tx
	b64 := resp.Data["signed_tx"].(string)
	bin, err := base64.StdEncoding.DecodeString(b64)
	assert.NoError(t, err)

	// Unmarshal in core.Transaction
	tx := &core.Transaction{}
	assert.NoError(t, proto.Unmarshal(bin, tx))

	// Only one contract
	assert.Len(t, tx.RawData.Contract, 1)
	c := tx.RawData.Contract[0]
	assert.Equal(t, core.Transaction_Contract_TriggerSmartContract, c.Type)

	// Check contract
	p := &core.TriggerSmartContract{}
	assert.NoError(t, anypb.UnmarshalTo(c.Parameter, p, proto.UnmarshalOptions{}))
	// owner and contract adddres need to be the same
	assert.Equal(t, trx.DecodeBase58(owner), p.OwnerAddress)
	assert.Equal(t, trx.DecodeBase58(owner), p.ContractAddress)
	assert.Equal(t, int64(0), p.CallValue)
	// feeLimit check from RawData
	assert.Equal(t, int64(2000000), tx.RawData.FeeLimit)

	// Let's check that we have correct token transfer
	assert.Len(t, tx.Signature, 1)
	// And tx_id — this is the hash of the transaction
	idHex := resp.Data["tx_id"].(string)
	_, err = hex.DecodeString(idHex)
	assert.NoError(t, err)
}
