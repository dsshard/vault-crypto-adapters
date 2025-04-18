package eth

import (
	"bytes"
	"context"
	"fmt"
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// ERC20 ABI для метода transfer(address,uint256)
const erc20ABIJSON = `[{
  "constant": false,
  "inputs": [
    { "name": "_to", "type": "address" },
    { "name": "_value", "type": "uint256" }
  ],
  "name": "transfer",
  "outputs": [{ "name": "", "type": "bool" }],
  "type": "function"
}]`

func PathTransferERC20() *framework.Path {
	return &framework.Path{
		Pattern:        config.CreatePathTransferToken(config.Chain.ETH),
		ExistenceCheck: backend.PathExistenceCheck,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: transferERC20},
		},
		HelpSynopsis:    "Sign an ERC‑20 token transfer",
		HelpDescription: "POST _serviceName_, _tokenAddress_, _to_, _value_(wei), optional _nonce_, _gasPrice_, _gas_, _chainId_",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Service name (key‑manager identifier).",
			},
			"tokenAddress": {
				Type:        framework.TypeString,
				Description: "Contract address of the token.",
			},
			"to": {
				Type:        framework.TypeString,
				Description: "Address of the recipient.",
			},
			"value": {
				Type:        framework.TypeString,
				Description: "Sum to transfer in wei.",
			},
			"nonce": {
				Type:        framework.TypeString,
				Description: "(Optional) Nonce of the transaction. If not provided, it will be fetched from the network.",
				Default:     "0",
			},
			"gasPrice": {
				Type:        framework.TypeString,
				Description: "(optional) GasPrice в wei.",
				Default:     "0",
			},
			"gas": {
				Type:        framework.TypeString,
				Description: "(optional) Gas limit.",
				Default:     "90000",
			},
			"chainId": {
				Type:        framework.TypeString,
				Description: "(optional) ChainID for EIP‑155.",
				Default:     "0",
			},
		},
	}
}

func transferERC20(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	// Парсим вход
	svc := data.Get("name").(string)
	tokenAddr := data.Get("tokenAddress").(string)
	toAddr := data.Get("to").(string)
	valueStr := data.Get("value").(string)

	// Конвертация чисел
	nonce := ValidNumber(data.Get("nonce").(string)).Uint64()
	gasLimit := ValidNumber(data.Get("gas").(string)).Uint64()
	gasPrice := ValidNumber(data.Get("gasPrice").(string))
	chainID := ValidNumber(data.Get("chainId").(string))

	// Получаем KeyManager
	km, err := backend.RetrieveKeyManager(ctx, req, config.Chain.ETH, svc)
	if err != nil {
		return nil, err
	}
	if km == nil {
		return nil, fmt.Errorf("keyManager %s not found", svc)
	}

	// Ищем приватник по первому адресу (можно по аргументу тоже)
	privHex := km.KeyPairs[0].PrivateKey
	priv, err := crypto.HexToECDSA(privHex)
	if err != nil {
		return nil, err
	}
	defer ZeroKey(priv)

	// Парсим ABI и собираем data
	contractAbi, err := abi.JSON(strings.NewReader(erc20ABIJSON))
	if err != nil {
		return nil, err
	}
	to := common.HexToAddress(toAddr)
	val := ValidNumber(valueStr)
	payload, err := contractAbi.Pack("transfer", to, val)
	if err != nil {
		return nil, err
	}

	// Собираем транзакцию EIP‑155
	toToken := common.HexToAddress(tokenAddr)
	var tx *types.Transaction
	if chainID.Cmp(big.NewInt(0)) == 0 {
		// Homestead
		tx = types.NewTx(&types.LegacyTx{
			Nonce:    nonce,
			GasPrice: gasPrice,
			Gas:      gasLimit,
			To:       &toToken,
			Value:    big.NewInt(0),
			Data:     payload,
		})
	} else {
		// EIP‑155
		tx = types.NewTx(&types.LegacyTx{
			Nonce:    nonce,
			GasPrice: gasPrice,
			Gas:      gasLimit,
			To:       &toToken,
			Value:    big.NewInt(0),
			Data:     payload,
		})
	}

	// Подпись
	var signer types.Signer
	if chainID.Cmp(big.NewInt(0)) == 0 {
		signer = types.HomesteadSigner{}
	} else {
		signer = types.NewEIP155Signer(chainID)
	}

	signed, err := types.SignTx(tx, signer, priv)
	if err != nil {
		return nil, err
	}

	// RLP → hex
	var buf bytes.Buffer
	if err := signed.EncodeRLP(&buf); err != nil {
		return nil, err
	}
	signedHex := hexutil.Encode(buf.Bytes())

	return &logical.Response{
		Data: map[string]interface{}{
			"txHash":   signed.Hash().Hex(),
			"signedTx": signedHex,
		},
	}, nil
}
