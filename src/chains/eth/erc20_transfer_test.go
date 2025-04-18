package eth_test

import (
	"bytes"
	"context"
	"github.com/dsshard/vault-crypto-adapters/src/chains/eth"
	common2 "github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestEthERC20Transfer(t *testing.T) {
	b, storage := common2.NewTestBackend(t)

	const svc = "svc-erc20"

	// 1) Create key‑manager
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/eth")
	req.Storage = storage
	req.Data = map[string]interface{}{"serviceName": svc}
	_, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 2) Transfer 10 tokens (decimals 18) of a dummy contract
	contract := "0x1111111111111111111111111111111111111111"
	to := "0x2222222222222222222222222222222222222222"
	req = logical.TestRequest(t, logical.CreateOperation, "key-managers/eth/"+svc+"/transfer/token")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"tokenAddress": contract,
		"to":           to,
		"value":        "10000000000000000000", // 10 * 1e18
		"nonce":        "0",
		"gasPrice":     "0",
		"gas":          "60000",
		"chainId":      "1",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// 3) Decode signedTx and verify signature
	signedHex := resp.Data["signedTx"].(string)
	sigBytes, err := hexutil.Decode(signedHex)
	require.NoError(t, err)

	tx := new(types.Transaction)
	err = tx.DecodeRLP(rlp.NewStream(bytes.NewReader(sigBytes), 0))
	require.NoError(t, err)

	v, _, _ := tx.RawSignatureValues()
	assert.True(t, eth.Contains([]*big.Int{big.NewInt(37), big.NewInt(38)}, v),
		"v value %d not in expected {37,38}", v)

	// 4) Check that to address and value in payload match
	// Decode input data
	data := tx.Data()
	// For ERC20 transfer, function selector is first 4 bytes
	require.Len(t, data, 4+32+32)
	// Last 20 bytes of first 32‑byte word is 'to' address
	argTo := common.HexToAddress(hexutil.Encode(data[4+12 : 4+32]))
	assert.Equal(t, to, argTo.Hex())
	// Next 32 bytes is value
	valBig := new(big.Int).SetBytes(data[4+32 : 4+64])
	assert.Equal(t, big.NewInt(0).Mul(big.NewInt(10), big.NewInt(1e18)), valBig)
}
