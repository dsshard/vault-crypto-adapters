package sol_test

import (
	"context"
	"encoding/hex"
	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestSolSign(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// create key manager
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/sol/svc")
	req.Storage = storage
	account, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// arbitrary message
	msg := "deadbeef"
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/sol/svc/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":    msg,
		"address": account.Data["address"],
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	sigHex, ok := resp.Data["signature"].(string)
	require.True(t, ok, "expected signature string")

	sig, err := hex.DecodeString(sigHex)
	require.NoError(t, err)
	// ED25519 signature is 64 bytes
	assert.Len(t, sig, 64)
}
