package xrp_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXrpSignBlob(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// 1) Create/import a key‐manager for XRP
	req := logical.TestRequest(t, logical.CreateOperation, "key-managers/xrp/svc")
	req.Storage = storage
	account, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 2) Sign a zero‐blob (32 bytes of 0x00)
	zeroBlob := hex.EncodeToString(make([]byte, 32))
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/xrp/svc/sign")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"hash":    zeroBlob,
		"address": account.Data["address"],
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	sigHex := resp.Data["signature"].(string)
	sig, err := hex.DecodeString(sigHex)
	require.NoError(t, err)

	// 3) Verify we got a non‐empty DER‐encoded ECDSA signature
	assert.NotEmpty(t, sig)
	// first byte of DER sig should be 0x30 (ASN.1 SEQUENCE)
	assert.Equal(t, byte(0x30), sig[0])
}
