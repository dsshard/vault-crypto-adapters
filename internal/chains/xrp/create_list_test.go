package xrp_test

import (
	"context"
	"log"
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
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/xrp")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "90dc3e2382d825f290148356dbbe315135dc0fe60bb17030edd2ea6127f938d5",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)

	log.Print(addr)
	// must be a 0x-prefixed 40‑hex‑char address
	assert.Equal(t, "rh8Xyr355XDm5PCMzD1qWcjd5b5GqLpdqm", addr)

	// 2) Generate another key (no privateKey → new random)
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/xrp")
	req.Storage = storage
	req.Data = map[string]interface{}{"service_name": "svc"}
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 3) List service names
	req = logical.TestRequest(t, logical.ListOperation, "key-managers/xrp")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, []string{"svc"}, resp.Data["keys"].([]string))

	// 4) Read all addresses under "svc"
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/xrp/svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addrs := resp.Data["addresses"].([]string)
	assert.Len(t, addrs, 2)
	for _, a := range addrs {
		// eth regexp
		assert.Regexp(t, regexp.MustCompile(`^r[1-9A-HJ-NP-Za-km-z]{25,34}$`), a)
	}
}

func TestXrpCreateAndListKeyManagers_EmptyPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// empty privateKey → should generate a new random Ethereum address
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/xrp")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	assert.Regexp(t, `^r[1-9A-HJ-NP-Za-km-z]{25,34}$`, addr)
}

func TestXrpCreateAndListKeyManagers_InvalidPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// too-short or malformed privkey → error
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/xrp")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "1234deadbeef",
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}
