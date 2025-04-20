package eth_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEthCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// 1) Import a specific 32‑byte hex privkey (no 0x prefix)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/eth")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	// must be a 0x-prefixed 40‑hex‑char address
	assert.Equal(t, "0x90Be49D363130726040fC1d05Ea29Fd090e0c8F0", addr)

	// 2) Generate another key (no privateKey → new random)
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/eth")
	req.Storage = storage
	req.Data = map[string]interface{}{"service_name": "svc"}
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 3) List service names
	req = logical.TestRequest(t, logical.ListOperation, "key-managers/eth")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, []string{"svc"}, resp.Data["keys"].([]string))

	// 4) Read all addresses under "svc"
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/eth/svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addrs := resp.Data["addresses"].([]string)
	assert.Len(t, addrs, 2)
	for _, a := range addrs {
		// eth regexp
		assert.Regexp(t, regexp.MustCompile(`^0x[0-9A-Fa-f]{40}$`), a)
	}
}

func TestEthCreateAndListKeyManagers_EmptyPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// empty privateKey → should generate a new random Ethereum address
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/eth")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	assert.Regexp(t, `^0x[0-9A-Fa-f]{40}$`, addr)
}

func TestEthCreateAndListKeyManagers_InvalidPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// too-short or malformed privkey → error
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/eth")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "1234deadbeef",
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}
