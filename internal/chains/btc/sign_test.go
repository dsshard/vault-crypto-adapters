package btc_test

import (
	"context"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBtcSignHash(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	// create
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/btc")
	req.Storage = storage
	req.Data = map[string]interface{}{"service_name": "svc"}
	account, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// sign zero hash
	zeroHash := hex.EncodeToString(make([]byte, 32))
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/btc/svc/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"name":    "svc",
		"hash":    zeroHash,
		"address": account.Data["address"],
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	sig, _ := hex.DecodeString(resp.Data["signature"].(string))
	assert.Len(t, sig, schnorr.SignatureSize)
}
