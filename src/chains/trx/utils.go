package trx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/sha3"
)

var (
	errInvalidType = errors.New("invalid input type")
)

func DeriveAddress(pub *ecdsa.PublicKey) string {
	raw := elliptic.Marshal(btcec.S256(), pub.X, pub.Y)
	// 2) Keccak256(X||Y) и берём последние 20 байт
	h := sha3.NewLegacyKeccak256()
	h.Write(raw[1:])
	addrHash := h.Sum(nil)[12:]
	// 3) Добавляем версию 0x41 и считаем двойной SHA256 checksum
	versioned := append([]byte{0x41}, addrHash...)
	// 4) Двойной SHA256 для контрольной суммы
	cs1 := sha256.Sum256(versioned)
	cs2 := sha256.Sum256(cs1[:])
	// 5) Финальный байтовый массив = versioned || cs2[0:4]
	full := append(versioned, cs2[0:4]...)
	// 4) Base58Encode
	return base58.Encode(full)
}

// DecodeBase58 декодирует Base58Check‑строку, отбрасывает версию+checksum
func DecodeBase58(addr string) []byte {
	full := base58.Decode(addr)
	if len(full) < 5 {
		return nil
	}
	return full[1 : len(full)-4]
}

func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}
