package eth_test

import (
	"bytes"
	"context"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/chains/eth"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestEthTransfer(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	const svc = "svc-eth"

	// 1) Create key‑manager
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/eth")
	req.Storage = storage
	req.Data = map[string]interface{}{"serviceName": svc}

	resp1, err := b.HandleRequest(context.Background(), req)

	require.NoError(t, err)

	// 2) Transfer 0.1 ETH (in wei), minimal params
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/eth/"+svc+"/transfer")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"address":  resp1.Data["address"].(string),
		"to":       "0x6Ecbe1DB9EF729CBe972C83Fb886247691Fb6beb",
		"value":    "100000000000000000", // 0.1 ETH
		"nonce":    "0",
		"gasPrice": "0",
		"gas":      "21000",
		"chainId":  "1",
	}
	resp, err := b.HandleRequest(context.Background(), req)

	require.NoError(t, err)

	// 3) Decode signedTx and verify signature values
	signedHex := resp.Data["signedTx"].(string)
	sigBytes, err := hexutil.Decode(signedHex)
	require.NoError(t, err)

	tx := new(types.Transaction)
	err = tx.DecodeRLP(rlp.NewStream(bytes.NewReader(sigBytes), 0))
	require.NoError(t, err)

	v, _, _ := tx.RawSignatureValues()
	// v should be 37 or 38 for chainId=1
	assert.True(t, eth.Contains([]*big.Int{big.NewInt(37), big.NewInt(38)}, v),
		"v value %d not in expected {37,38}", v)

	// And sender recovers correctly
	sender, err := types.Sender(types.NewEIP155Signer(big.NewInt(1)), tx)
	require.NoError(t, err)
	// we created only one keypair, so its address is first in list
	km, err := backend.RetrieveKeyManager(context.Background(), req, config.Chain.ETH, svc)
	require.NoError(t, err)
	expected := km.KeyPairs[0].Address
	assert.Equal(t, expected, sender.Hex())
}
