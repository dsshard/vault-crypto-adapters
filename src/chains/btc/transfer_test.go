package btc_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"github.com/dsshard/vault-crypto-adapters/src/test"
	localTypes "github.com/dsshard/vault-crypto-adapters/src/types"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBtcTransfer(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// Create key-manager
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/btc")
	req.Storage = storage
	req.Data = map[string]interface{}{"serviceName": "svc"}
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// Retrieve stored KeyManager to get private key
	entry, err := storage.Get(context.Background(), "key-managers/btc/svc")
	require.NoError(t, err)
	var km localTypes.KeyManager
	require.NoError(t, entry.DecodeJSON(&km))
	privBytes, err := hex.DecodeString(km.KeyPairs[0].PrivateKey)
	require.NoError(t, err)

	// Dummy BTC transfer: returns base64(privkey) as signed_tx and SHA256(privkey) as txid
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/btc/svc/transfer")
	req.Storage = storage
	req.Data = map[string]interface{}{"name": "svc"}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	signedB64 := resp.Data["signed_tx"].(string)
	gotBytes, err := base64.StdEncoding.DecodeString(signedB64)
	require.NoError(t, err)
	assert.Equal(t, privBytes, gotBytes)

	sum := sha256.Sum256(privBytes)
	wantTxID := hex.EncodeToString(sum[:])
	assert.Equal(t, wantTxID, resp.Data["txid"].(string))
}
