package trx_test

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/fbsobreira/gotron-sdk/pkg/proto/core"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"testing"
)

func TestTrxTransferTx(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// Create manager
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
	toAddr := resp.Data["addresses"].([]string)[0]

	// Build & sign transfer
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/trx/svc/transfer")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"name":     "svc",
		"to":       toAddr,
		"amount":   "1000",
		"feeLimit": 1000000,
	}
	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)

	// Decode signed_tx
	b64 := resp.Data["signed_tx"].(string)
	bin, err := base64.StdEncoding.DecodeString(b64)
	assert.NoError(t, err)

	tx := &core.Transaction{}
	err = proto.Unmarshal(bin, tx)
	assert.NoError(t, err)

	// Check tx
	assert.Len(t, tx.RawData.Contract, 1)
	assert.Len(t, tx.Signature, 1)
	txID := resp.Data["tx_id"].(string)
	_, err = hex.DecodeString(txID)
	assert.NoError(t, err)
}
