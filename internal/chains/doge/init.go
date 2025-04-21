package doge

import (
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
)

func init() {
	backend.Register(config.Chain.DOGE, backend.Endpoints{
		Crud: PathCrud,
		Sign: PathSign,
	})
}
