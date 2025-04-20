package eth

import (
	"crypto/ecdsa"
)

type Nonce struct {
	ConfirmedNonce uint64
	PendingNonce   uint64
}

func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
