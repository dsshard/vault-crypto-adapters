package xrp_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXrpCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// 1) Import a specific 32‑byte hex privkey (no 0x prefix)
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/xrp/svc")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"private_key": "90dc3e2382d825f290148356dbbe315135dc0fe60bb17030edd2ea6127f938d5",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)

	// must be a 0x-prefixed 40‑hex‑char address
	assert.Equal(t, "rh8Xyr355XDm5PCMzD1qWcjd5b5GqLpdqm", addr)

	// 2) Generate another key (no privateKey → new random)
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/xrp/svc")
	req.Storage = storage
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 4) Read all addresses under "svc"
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/xrp/svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	rawPairs, ok := resp.Data["key_pairs"].([]map[string]interface{})
	require.True(t, ok, "expected key_pairs to be []map[string]string")
	require.Len(t, rawPairs, 2)

	// потом из каждого interface{} получаем map[string]interface{}:
	for _, pair := range rawPairs {
		addr := pair["address"]

		// проверяем адрес и pubkey как раньше
		assert.Regexp(t, regexp.MustCompile(`^r[1-9A-HJ-NP-Za-km-z]{25,34}$`), addr)
	}
}

func TestXrpCreateAndListKeyManagers_EmptyPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// empty privateKey → should generate a new random Ethereum address
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/xrp/svc")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"private_key": "",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	assert.Regexp(t, `^r[1-9A-HJ-NP-Za-km-z]{25,34}$`, addr)
}

func TestXrpCreateAndListKeyManagers_InvalidPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// too-short or malformed privkey → error
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/xrp/svc")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"private_key": "1234deadbeef",
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}
