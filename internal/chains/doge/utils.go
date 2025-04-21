package doge

import (
	"crypto/sha256"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

// DeriveAddress builds a P2PKH Dogecoin address (starts with "D")
func DeriveAddress(pub *btcec.PublicKey) (string, error) {
	// compressed pubkey 33 bytes
	pubBytes := pub.SerializeCompressed()
	// SHA256
	h1 := sha256.Sum256(pubBytes)
	// RIPEMD160
	r := ripemd160.New()
	r.Write(h1[:])
	h160 := r.Sum(nil)
	// version byte for Doge P2PKH is 0x1E
	versioned := append([]byte{0x1E}, h160...)
	// checksum = first 4 of double SHA256
	c1 := sha256.Sum256(versioned)
	c2 := sha256.Sum256(c1[:])
	full := append(versioned, c2[:4]...)
	// Base58Check
	addr := base58.Encode(full)
	return addr, nil
}
