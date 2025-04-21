package btc

import (
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
)

func init() {
	backend.Register(config.Chain.BTC, backend.Endpoints{
		Crud: PathCrud,
		Sign: PathSign,
	})
}
