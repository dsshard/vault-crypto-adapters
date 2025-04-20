package btc_test

import (
	"context"
	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBtcCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	// Import specific privkey
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/btc")
	req.Storage = storage
	// 32‑byte secp256k1 privkey hex
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "KzQJ9vR4JeoJicejXmdvjcoDmZHa665diNxt17o3KRw3Hvix5CA5",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	addr := resp.Data["address"].(string)
	assert.Equal(t, "bc1qyr5sfdeg3570txvn7adftehdqz74fm7t8flp03k8d6xwhf8kkd9xd4y073", addr)

	// Generate another key
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/btc")
	req.Storage = storage
	req.Data = map[string]interface{}{"service_name": "svc"}
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// List
	req = logical.TestRequest(t, logical.ListOperation, "key-managers/btc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	//log resp

	require.NoError(t, err)
	assert.Equal(t, []string{"svc"}, resp.Data["keys"].([]string))

	// Read
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/btc/svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	addrs := resp.Data["addresses"].([]string)
	assert.Len(t, addrs, 2)
}

func TestBtcCreateAndListKeyManagers2(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	// Import specific privkey
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/btc")
	req.Storage = storage
	// 32‑byte secp256k1 privkey hex
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	addr := resp.Data["address"].(string)
	// bitcoin mainnet taproot address regexp
	assert.Regexp(t, `^bc1[a-z0-9]{39,}$`, addr)
}

func TestBtcCreateAndListKeyManagers3(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	// Import specific privkey
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/btc")
	req.Storage = storage
	// 32‑byte secp256k1 privkey hex
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "123",
	}

	_, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}
