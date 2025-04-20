package ton_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTonSignHash(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// Create manager
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/ton")
	req.Storage = storage
	req.Data = map[string]interface{}{"service_name": "svc"}
	account, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// Sign zero‑hash
	zeroHash := hex.EncodeToString(make([]byte, 32))
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/ton/svc/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"name":    "svc",
		"hash":    zeroHash,
		"address": account.Data["address"],
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	sigHex := resp.Data["signature"].(string)
	sig, err := hex.DecodeString(sigHex)
	require.NoError(t, err)
	assert.Len(t, sig, ed25519.SignatureSize)
}
