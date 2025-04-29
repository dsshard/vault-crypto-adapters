package trx_test

import (
	"context"
	"encoding/hex"
	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTrxSignHash(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// Create manager
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/trx/svc")
	req.Storage = storage
	account, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)

	// Get address
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/trx/svc")
	req.Storage = storage
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)

	// Sign a zero‐hash
	zeroHash := hex.EncodeToString(make([]byte, 32))
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/trx/svc/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":    zeroHash,
		"address": account.Data["address"],
	}
	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	sig, _ := hex.DecodeString(resp.Data["signature"].(string))
	assert.Len(t, sig, 65)
}
