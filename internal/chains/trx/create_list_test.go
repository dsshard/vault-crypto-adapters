package trx_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrxCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// 1) Import a specific 32‑byte secp256k1 private key (64 hex chars, no 0x)
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/trx/svc")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"private_key": "4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	// Tron addresses are Base58Check, start with 'T' and are 34 chars long
	assert.Equal(t, "TPAYG9ifQaU2T8zNtVqzyzgzKrvawPCwpd", addr)

	// 2) Generate another key (empty privateKey → new random)
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/trx/svc")
	req.Storage = storage
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 4) Read all addresses under "svc"
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/trx/svc")
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
		assert.Regexp(t, regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`), addr)
	}
}

func TestTrxCreateAndListKeyManagers_EmptyPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// empty privateKey → should generate a new random Tron address
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/trx/svc")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"private_key": "",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	assert.Regexp(t, regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`), addr)
}

func TestTrxCreateAndListKeyManagers_InvalidPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// too-short or malformed privateKey → error
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/trx/svc")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"private_key": "1234deadbeef",
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}
