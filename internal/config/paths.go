package config

import (
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
)

func GetStoragePath(chain ChainType, service string) string {
	return fmt.Sprintf("key-managers/%s/%s", chain, service)
}

func CreatePathCrud(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/%s", chain, framework.GenericNameRegex("name"))
}

func CreatePathCrudList(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s", chain)
}

func CreatePathUpdateExternalData(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/%s/external", chain, framework.GenericNameRegex("name"))
}

func CreatePathSign(chain ChainType) string {
	return fmt.Sprintf("key-managers/%s/%s/sign", chain, framework.GenericNameRegex("name"))
}
