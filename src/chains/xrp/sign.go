package xrp

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	ripplecrypto "github.com/rubblelabs/ripple/crypto"
)

func PathSign() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathSign(config.Chain.XRP),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: signTransaction},
		},
		HelpSynopsis:    "Sign an XRP transaction blob",
		HelpDescription: "POST serviceName + address + txBlob(hex) → signature(hex)",
		Fields:          backend.DefaultSignOperation,
	}
}

func signTransaction(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name, hashInput, address, err := backend.GetSignParamsFromData(data)

	if err != nil {
		return nil, fmt.Errorf("serviceName, address and txBlob are required")
	}

	// 1) Load KeyManager
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.XRP, name)
	if err != nil {
		return nil, err
	}
	if km == nil {
		return nil, fmt.Errorf("service %q not found", name)
	}

	// 2) Find the requested private key (32‑byte hex seed → secp256k1 d)
	var privBytes []byte
	for _, kp := range km.KeyPairs {
		if kp.Address == address {
			privBytes, err = hex.DecodeString(kp.PrivateKey)
			if err != nil {
				return nil, fmt.Errorf("stored privateKey is invalid hex: %w", err)
			}
			break
		}
	}
	if privBytes == nil {
		return nil, fmt.Errorf("address %q not found under service %q", address, name)
	}

	// 3) Decode transaction blob
	txBytes, err := hex.DecodeString(hashInput)
	if err != nil {
		return nil, fmt.Errorf("invalid txBlob hex: %w", err)
	}

	// XRP uses the first 32 bytes of SHA-512Half(txBytes)
	hash := ripplecrypto.Sha512Half(txBytes)

	// rebuild PrivKey
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)

	// 🚀 Here's the ECDSA Sign call from btcec/v2/ecdsa:
	sig := ecdsa.Sign(privKey, hash) // :contentReference[oaicite:0]{index=0}

	// and you can DER‑serialize it directly:
	sigBytes := sig.Serialize() // :contentReference[oaicite:1]{index=1}
	sigHex := hex.EncodeToString(sigBytes)

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": sigHex,
		},
	}, nil
}
