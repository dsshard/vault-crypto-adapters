package ton_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTonTransferTon(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// Create manager
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/ton")
	req.Storage = storage
	req.Data = map[string]interface{}{"serviceName": "svc"}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	addr := resp.Data["address"].(string)
	require.NotEmpty(t, addr)

	// Dummy TON transfer: returns seed as BOC
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/ton/svc/transfer")
	req.Storage = storage
	req.Data = map[string]interface{}{"name": "svc"}
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	b64 := resp.Data["signed_boc"].(string)
	bocBytes, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	require.NotEmpty(t, bocBytes)

	// Compute expected msg_id
	sum := sha256.Sum256(bocBytes)
	wantID := hex.EncodeToString(sum[:])
	gotID := resp.Data["msg_id"].(string)
	assert.Equal(t, wantID, gotID)
}
