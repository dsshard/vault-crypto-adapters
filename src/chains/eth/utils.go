package eth

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common/math"
	"math/big"
	"regexp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type Nonce struct {
	ConfirmedNonce uint64
	PendingNonce   uint64
}

func newTransactionWithDynamicFee(
	to *common.Address,
	nonce uint64,
	gasFeeCap *big.Int,
	gasTipCap *big.Int,
	gas uint64,
	data []byte,
	value *big.Int,
) *types.Transaction {
	return types.NewTx(&types.DynamicFeeTx{
		To:        to,
		Nonce:     nonce,
		GasFeeCap: gasFeeCap,
		GasTipCap: gasTipCap,
		Gas:       gas,
		Value:     value,
		Data:      data,
	})
}

func newLegacyTransaction(
	to *common.Address,
	nonce uint64,
	gasPrice *big.Int,
	gas uint64,
	data []byte,
	value *big.Int,
) *types.Transaction {
	return types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gas,
		To:       to,
		Value:    value,
		Data:     data,
	})
}

func ValidNumber(input string) *big.Int {
	if input == "" {
		return big.NewInt(0)
	}
	matched, err := regexp.MatchString("([0-9])", input)
	if !matched || err != nil {
		return nil
	}
	amount, ok := math.ParseBig256(input)
	if !ok {
		return nil
	}
	return amount.Abs(amount)
}

func Contains(arr []*big.Int, value *big.Int) bool {
	for _, a := range arr {
		if a.Cmp(value) == 0 {
			return true
		}
	}
	return false
}

func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
