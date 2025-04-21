package doge_test

import (
	"context"
	"encoding/hex"
	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDogeSignHash(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// 1) Create/import a Doge key‐manager for service "svc"
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/doge/svc")
	req.Storage = storage
	account, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)
	addr := account.Data["address"].(string)

	// 2) Sign a zero‐hash (32 bytes of 0x00)
	zeroHash := hex.EncodeToString(make([]byte, 32))
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/doge/svc/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":    zeroHash,
		"address": addr,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 3) Decode signature and verify it's a DER‐encoded ECDSA sig
	sigHex := resp.Data["signature"].(string)
	sig, err := hex.DecodeString(sigHex)
	require.NoError(t, err)

	// Must not be empty
	assert.NotEmpty(t, sig)
	// DER signatures start with 0x30 (ASN.1 SEQUENCE)
	assert.Equal(t, byte(0x30), sig[0])
}
