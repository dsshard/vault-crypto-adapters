package ton

import (
	"crypto/ed25519"
	"fmt"
	"github.com/tonkeeper/tongo/wallet"
)

// DeriveAddress TonDeriveAddress берёт Ed25519 pub‑key и возвращает bounceable‑friendly TON‑адрес.
func DeriveAddress(pub ed25519.PublicKey) string {
	addr, err := wallet.GenerateWalletAddress(pub, wallet.V4R2, nil, 0, nil)
	if err != nil {
		panic(fmt.Sprintf("TonDeriveAddress: %v", err))
	}
	return addr.ToHuman(true, false)
}
