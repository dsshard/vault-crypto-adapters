package backend

import (
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/hashicorp/vault/sdk/framework"
)

// Endpoints описывает пару CRUD/Sign для одной монеты
type Endpoints struct {
	Crud func() *framework.Path
	Sign func() *framework.Path
}

// registry хранит зарегистрированные эндпоинты
var registry = map[config.ChainType]Endpoints{}

// Register вызывают из каждого coin-пакета в init()
func Register(chain config.ChainType, e Endpoints) {
	registry[chain] = e
}

// All возвращает копию реестра
func All() map[config.ChainType]Endpoints {
	out := make(map[config.ChainType]Endpoints, len(registry))
	for k, v := range registry {
		out[k] = v
	}
	return out
}
