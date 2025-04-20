package trx_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrxCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// 1) Import a specific 32‑byte secp256k1 private key (64 hex chars, no 0x)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/trx")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	// Tron addresses are Base58Check, start with 'T' and are 34 chars long
	assert.Equal(t, "TPAYG9ifQaU2T8zNtVqzyzgzKrvawPCwpd", addr)

	// 2) Generate another key (empty privateKey → new random)
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/trx")
	req.Storage = storage
	req.Data = map[string]interface{}{"service_name": "svc"}
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 3) List service names
	req = logical.TestRequest(t, logical.ListOperation, "key-managers/trx")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, []string{"svc"}, resp.Data["keys"].([]string))

	// 4) Read all addresses under "svc"
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/trx/svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addrs := resp.Data["addresses"].([]string)
	assert.Len(t, addrs, 2)
	for _, a := range addrs {
		assert.Regexp(t, regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`), a)
	}
}

func TestTrxCreateAndListKeyManagers_EmptyPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// empty privateKey → should generate a new random Tron address
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/trx")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	assert.Regexp(t, regexp.MustCompile(`^T[1-9A-HJ-NP-Za-km-z]{33}$`), addr)
}

func TestTrxCreateAndListKeyManagers_InvalidPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// too-short or malformed privateKey → error
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/trx")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "1234deadbeef",
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}
