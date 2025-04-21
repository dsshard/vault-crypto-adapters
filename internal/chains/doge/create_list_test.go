package doge_test

import (
	"context"
	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDogeCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	// Import specific privkey
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/doge/svc")
	req.Storage = storage
	// 32‑byte secp256k1 privkey hex
	req.Data = map[string]interface{}{
		"private_key": "KzQJ9vR4JeoJicejXmdvjcoDmZHa665diNxt17o3KRw3Hvix5CA5",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	addr := resp.Data["address"].(string)
	assert.Equal(t, "D9CJPqih9zaKTTgpY1msoQRBUjDbEXNvtJ", addr)

	// Generate another key
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/doge/svc")
	req.Storage = storage
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// Read
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/doge/svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	// приводим к []interface{} и проверяем длину
	rawPairs := resp.Data["key_pairs"].([]map[string]string)
	require.Len(t, rawPairs, 2)
}

func TestDogeCreateAndListKeyManagers2(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	// Import specific privkey
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/doge/svg")
	req.Storage = storage
	// 32‑byte secp256k1 privkey hex
	req.Data = map[string]interface{}{
		"private_key": "",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	addr := resp.Data["address"].(string)
	// bitcoin mainnet taproot address regexp
	assert.Regexp(t, `^(D|A|9)[a-km-zA-HJ-NP-Z1-9]{33,34}$`, addr)
}

func TestDogeCreateAndListKeyManagers3(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	// Import specific privkey
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/doge/svc")
	req.Storage = storage
	// 32‑byte secp256k1 privkey hex
	req.Data = map[string]interface{}{
		"private_key": "123",
	}

	_, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}
