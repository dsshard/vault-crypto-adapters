package trx

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/dsshard/vault-crypto-adapters/internal/types"
	"github.com/ethereum/go-ethereum/log"
	"regexp"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func PathCrud() *framework.Path {
	return &framework.Path{
		Pattern: config.CreatePathCrud(config.Chain.TRX),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: createKeyManager,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: backend.WrapperReadKeyManager(config.Chain.TRX),
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: backend.WrapperDeleteKeyManager(config.Chain.TRX),
			},
		},
		HelpSynopsis:    backend.DefaultHelpHelpSynopsisCreateList,
		HelpDescription: backend.DefaultHelpDescriptionCreateList,
		Fields:          backend.DefaultCrudOperations,
	}
}

func createKeyManager(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	// Получаем serviceName
	serviceName, ok := data.Get("name").(string)
	if !ok {
		return nil, errors.New("invalid input type")
	}
	// Опциональный импорт приватного ключа
	privateKey, ok := data.Get("private_key").(string)
	if !ok {
		return nil, errInvalidType
	}

	// Проверяем, есть ли уже менеджер
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.TRX, serviceName)
	if err != nil {
		return nil, err
	}
	if km == nil {
		km = &types.KeyManager{ServiceName: serviceName}
	}

	// 1) Импорт или генерация приватного ключа
	var privateKeyExport *ecdsa.PrivateKey
	if privateKey != "" {
		m := regexp.MustCompile(`^[0-9a-fA-F]{64}$`).FindString(privateKey)
		if m == "" {
			return nil, fmt.Errorf("invalid private key")
		}
		bb, err := hex.DecodeString(m)
		if err != nil {
			return nil, fmt.Errorf("invalid privateKey hex: %w", err)
		}
		secpPriv, _ := btcec.PrivKeyFromBytes(bb)
		privateKeyExport = secpPriv.ToECDSA()
	} else {
		// случайная генерация
		var err error
		privateKeyExport, err = ecdsa.GenerateKey(btcec.S256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
	}
	defer ZeroKey(privateKeyExport)

	// 2) Собираем KeyPair
	privateBytes := privateKeyExport.D.Bytes()
	secpPriv, _ := btcec.PrivKeyFromBytes(privateBytes)
	pubKey := secpPriv.PubKey() // *btcec.PublicKey
	pubBytes := pubKey.SerializeUncompressed()
	ecdsaPub := pubKey.ToECDSA()
	address := DeriveAddress(ecdsaPub)

	kp := &types.KeyPair{
		PrivateKey: hex.EncodeToString(privateBytes),
		PublicKey:  hex.EncodeToString(pubBytes),
		Address:    address,
	}
	km.KeyPairs = append(km.KeyPairs, kp)

	// 3) Сохраняем в Vault
	path := fmt.Sprintf("key-managers/%s/%s", config.Chain.TRX, serviceName)
	entry, _ := logical.StorageEntryJSON(path, km)
	if err := req.Storage.Put(ctx, entry); err != nil {
		log.Error("Failed to store key-manager", "error", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"service_name": km.ServiceName,
			"address":      kp.Address,
			"public_key":   kp.PublicKey,
		},
	}, nil
}
