package chains

import (
	"github.com/dsshard/vault-crypto-adapters/src/backend"
	"github.com/dsshard/vault-crypto-adapters/src/chains/btc"
	"github.com/dsshard/vault-crypto-adapters/src/chains/eth"
	"github.com/dsshard/vault-crypto-adapters/src/chains/sol"
	"github.com/dsshard/vault-crypto-adapters/src/chains/ton"
	"github.com/dsshard/vault-crypto-adapters/src/chains/trx"
	"github.com/dsshard/vault-crypto-adapters/src/config"
	"github.com/hashicorp/vault/sdk/framework"
)

func Paths() []*framework.Path {
	return []*framework.Path{
		backend.PathReadAndDelete(config.Chain.TRX),
		backend.PathReadAndDelete(config.Chain.ETH),
		backend.PathReadAndDelete(config.Chain.BTC),
		backend.PathReadAndDelete(config.Chain.TON),
		backend.PathReadAndDelete(config.Chain.SOL),

		btc.PathCreateAndList(),
		btc.PathSign(),

		eth.PathCreateAndList(),
		eth.PathSign(),

		ton.PathCreateAndList(),
		ton.PathSign(),

		trx.PathCreateAndList(),
		trx.PathSign(),

		sol.PathCreateAndList(),
		sol.PathSignSol(),
	}
}
