package eth_test

import (
	"context"
	"encoding/hex"
	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEthSignHash(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	// create
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/eth")
	req.Storage = storage
	req.Data = map[string]interface{}{"service_name": "svc"}
	account, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// sign zero hash
	zeroHash := hex.EncodeToString(make([]byte, 32))
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/eth/svc/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"name":    "svc",
		"hash":    zeroHash,
		"address": account.Data["address"],
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	sig, _ := hex.DecodeString(resp.Data["signature"].(string))
	assert.NotEmpty(t, sig)
	assert.Len(t, sig, 65) // Обычно Ethereum ECDSA сигнатура составляет 65 байт
}
