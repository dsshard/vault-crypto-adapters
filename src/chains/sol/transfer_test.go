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

func TestSolTransfer(t *testing.T) {
	// setup in‐memory backend
	b, storage := test.NewTestBackend(t)
	const svc = "native"

	// 1) Create a Sol key‑manager
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/sol")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"serviceName": svc,
	}
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 2) Perform a native SOL transfer
	to := "2Poh8gF6PJhjNAa5bxPZHZgpYZbFvD8JQwyUyE48Q5cL"
	amount := "5000000000" // lamports
	blockhash := "AhaEpqfNpnbwmfTaZQTpjCerJAQe64ocf7Tqsf5AgTsK"
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/sol/"+svc+"/transfer")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"to":              to,
		"amount":          amount,
		"recentBlockhash": blockhash,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 3) Extract and decode the hex‑encoded transaction
	txHex, ok := resp.Data["tx"].(string)
	require.True(t, ok, "expected string in resp.Data[\"tx\"]")

	rawTx, err := hex.DecodeString(txHex)
	require.NoError(t, err)

	// 4) The first byte is the signature count (1)
	assert.Equal(t, byte(1), rawTx[0], "expected one signature")

	// 5) Ensure the transaction is non‐trivial length (has an instruction)
	assert.Greater(t, len(rawTx), 40, "serialized tx too short")

	// 6) Verify the signature bytes are not all zero
	sig := rawTx[1:65]
	nonZero := false
	for _, b := range sig {
		if b != 0 {
			nonZero = true
			break
		}
	}
	assert.True(t, nonZero, "signature should not be all zero")
}
