package sol_test

import (
	"context"
	"log"
	"regexp"
	"testing"

	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSolanaCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// 1) Import a specific 32‑byte Ed25519 seed as hex (64 hex chars)
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/sol")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "3b6a27bccebfb65a6d8c3e78bf84df3e7a32b29b77b680f7f245d3c5f5b0a1b2",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	// Solana pubkey is base58, 44 chars
	assert.Equal(t, "HqwjY6XnCGtHxPfiK684yHxHDmsrjKZ3sCJ5kzxgvscQ", addr)

	// 2) Generate another key (no privateKey → new random)
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/sol")
	req.Storage = storage
	req.Data = map[string]interface{}{"service_name": "svc"}
	_, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 3) List service names
	req = logical.TestRequest(t, logical.ListOperation, "key-managers/sol")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, []string{"svc"}, resp.Data["keys"].([]string))

	log.Print(resp)

	// 4) Read all addresses under "svc"
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/sol/svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addrs := resp.Data["addresses"].([]string)
	assert.Len(t, addrs, 2)
	for _, a := range addrs {
		assert.Regexp(t, regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`), a)
	}
}

func TestSolanaCreateAndListKeyManagers_EmptyPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// empty privateKey → should generate a new random Solana address
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/sol")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	addr := resp.Data["address"].(string)
	assert.Regexp(t, regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{44}$`), addr)
}

func TestSolanaCreateAndListKeyManagers_InvalidPrivKey(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// too-short or malformed privkey → error
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/sol")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"service_name": "svc",
		"private_key":  "1234deadbeef",
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")
}
