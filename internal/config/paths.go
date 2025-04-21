package config

import (
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
)

func CreatePathCrud(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/%s", chain, framework.GenericNameRegex("name"))
}

func CreatePathCrudDelete(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/%s/delete", chain, framework.GenericNameRegex("name"))
}

func CreatePathSign(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/%s/sign", chain, framework.GenericNameRegex("name"))
}
