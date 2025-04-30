package chains

import (
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	_ "github.com/dsshard/vault-crypto-adapters/internal/chains/btc"
	_ "github.com/dsshard/vault-crypto-adapters/internal/chains/doge"
	_ "github.com/dsshard/vault-crypto-adapters/internal/chains/eth"
	_ "github.com/dsshard/vault-crypto-adapters/internal/chains/sol"
	_ "github.com/dsshard/vault-crypto-adapters/internal/chains/ton"
	_ "github.com/dsshard/vault-crypto-adapters/internal/chains/trx"
	_ "github.com/dsshard/vault-crypto-adapters/internal/chains/xrp"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/hashicorp/vault/sdk/framework"
)

func Paths() []*framework.Path {
	var paths []*framework.Path

	// подхватываем все зарегистрированные coin-пакеты
	for _, chain := range config.AllChains {
		// Затем, если для этой цепочки есть специфичные CRUD/Sign
		if ep, ok := backend.All()[chain]; ok {
			paths = append(paths,
				ep.Crud(),
				ep.Sign(),
			)
		}
	}

	for _, chain := range config.AllChains {
		paths = append(paths, backend.PathCrudList(chain))
		paths = append(paths, backend.PathUpdateExternalData(chain))
	}

	return paths
}
