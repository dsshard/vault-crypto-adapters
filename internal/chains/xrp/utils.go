package xrp

import (
	"crypto/sha256"
	"golang.org/x/crypto/ripemd160"
	"math/big"
)

// base58Encode — простая реализация Base58Check с кастомным алфавитом.
func Base58Encode(data []byte, alphabet string) string {
	// convert big-endian bytes to big integer
	x := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	var result []byte
	for x.Cmp(zero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, base, mod)
		result = append(result, alphabet[mod.Int64()])
	}
	// leading zeros
	for _, b := range data {
		if b == 0 {
			result = append(result, alphabet[0])
		} else {
			break
		}
	}
	// reverse
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

// deriveClassicXRPAddress returns a Ripple “classic” address (starts with r)
func DeriveClassicXRPAddress(pub33 []byte) string {
	// SHA256 → RIPEMD160
	h1 := sha256.Sum256(pub33)
	// ignore
	//nolint:gosec
	rip := ripemd160.New()
	rip.Write(h1[:])
	accountID := rip.Sum(nil) // 20 байт

	// prepend version byte
	versioned := append([]byte{0x00}, accountID...)

	// checksum = first 4 от double SHA256
	cs1 := sha256.Sum256(versioned)
	cs2 := sha256.Sum256(cs1[:])

	const ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

	// 5) Base58 encode with Ripple’s alphabet
	return Base58Encode(append(versioned, cs2[:4]...), ALPHABET)
}
