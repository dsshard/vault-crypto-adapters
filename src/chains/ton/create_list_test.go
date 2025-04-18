package ton_test

import (
	"context"
	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTonCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// 1) Import specific privkey
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/ton")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"serviceName": "svc",
		"privateKey":  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	addr := resp.Data["address"].(string)
	require.NotEmpty(t, addr)

	// 2) Generate another key
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/ton")
	req.Storage = storage
	req.Data = map[string]interface{}{"serviceName": "svc"}
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 3) List
	req = logical.TestRequest(t, logical.ListOperation, "key-managers/ton")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	services := resp.Data["keys"].([]string)
	assert.Equal(t, []string{"svc"}, services)

	// 4) Read and check two addresses
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/ton/svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	addrs := resp.Data["addresses"].([]string)
	assert.Len(t, addrs, 2)
	assert.Contains(t, addrs, addr)
}
