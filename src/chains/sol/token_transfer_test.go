// internal/usecase/sol/path_transfer_token.go

package sol_test

import (
	"context"
	"encoding/hex"
	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestSolTransferToken(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	const svc = "tokener"

	// create key manager
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/sol")
	req.Storage = storage
	req.Data = map[string]interface{}{"serviceName": svc}
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// perform token transfer
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/sol/"+svc+"/transfer/token")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"mint":            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
		"to":              "3opE3EzAKnUftUDURkzMgwpNgimBAypW1mNDYH4x4Zg7",
		"amount":          "12345",
		"decimals":        "6",
		"recentBlockhash": "AhaEpqfNpnbwmfTaZQTpjCerJAQe64ocf7Tqsf5AgTsK",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	hexTx, ok := resp.Data["tx"].(string)
	require.True(t, ok, "expected tx hex string")

	raw, err := hex.DecodeString(hexTx)
	require.NoError(t, err)
	// Solana tx: first byte is number of signatures, should be 1
	require.GreaterOrEqual(t, len(raw), 1)
	assert.Equal(t, byte(1), raw[0])

	// ensure some instruction data is present after header (not empty)
	assert.True(t, len(raw) > 100, "serialized tx too short")
	// verify signature follows header: signature begins at byte 1..65
	sig := raw[1:65]
	assert.NotZero(t, sig[0], "signature should not be all zero")
}
