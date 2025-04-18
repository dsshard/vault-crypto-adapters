package config

import (
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
)

func CreatePathCreateListPattern(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/?", chain)
}

func CreatePathReadAndDelete(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/%s", chain, framework.GenericNameRegex("name"))
}

func CreatePathSign(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/%s/sign", chain, framework.GenericNameRegex("name"))
}

func CreatePathTransfer(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/%s/transfer", chain, framework.GenericNameRegex("name"))
}

func CreatePathTransferToken(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/%s/transfer/token", chain, framework.GenericNameRegex("name"))
}
