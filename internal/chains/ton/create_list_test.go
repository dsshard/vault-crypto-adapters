package ton_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTonCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// 1) Import a specific 32‑byte hex seed (no 0x prefix)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/ton")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		// this should be a 64‑hex‑char (32‑byte) seed
		"private_key": "4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b1",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	assert.Equal(t, "EQB2trRSt_ZF-gnMRgJhu_oORG6W0T8Ja75CmjnjRR1mRYL0", addr)

	// 2) Generate another key (empty privateKey → new random)
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/ton")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "",
	}
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 3) List service names
	req = logical.TestRequest(t, logical.ListOperation, "key-managers/ton")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, []string{"svc"}, resp.Data["keys"].([]string))

	// 4) Read all addresses under "svc"
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/ton/svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addrs := resp.Data["addresses"].([]string)
	assert.Len(t, addrs, 2)
	for _, a := range addrs {
		assert.Regexp(t, regexp.MustCompile(`^[A-Za-z0-9_-]{46,50}$`), a)
	}
}

func TestTonCreateAndListKeyManagers_EmptyPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// empty privateKey → new random TON address
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/ton")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	assert.Regexp(t, regexp.MustCompile(`^[A-Za-z0-9_-]{46,50}$`), addr)
}

func TestTonCreateAndListKeyManagers_InvalidPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// malformed/too‑short seed → error
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/ton")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "1234dead",
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}
