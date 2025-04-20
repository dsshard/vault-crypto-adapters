package btc

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// DeriveAddress BtcDeriveAddress builds a native‐SegWit v1 (Taproot) address (bc1p...)
func DeriveAddress(pub *btcec.PublicKey) (string, error) {
	// 1) Get the 33‑byte compressed pubkey, drop the 0x02/0x03 prefix → 32 bytes x-only
	comp := pub.SerializeCompressed() // [0x02/0x03 || X(32)]
	xOnly := comp[1:]                 // 32 bytes

	// 2) Build the witness program: version=1 || data=xOnly
	program := append([]byte{0x01}, xOnly...)

	// 3) Convert from 8‑bit to 5‑bit groups (per BIP‑173/BIP‑350)
	data5, err := bech32.ConvertBits(program, 8, 5, true)
	if err != nil {
		return "", err
	}

	// 4) bech32m‐Encode with HRP "bc" (for mainnet). Use "tb" for testnet.
	addr, err := bech32.EncodeM("bc", data5)
	if err != nil {
		return "", err
	}
	return addr, nil
}
