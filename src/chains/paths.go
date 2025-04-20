package chains

import (
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
		PathReadAndDelete(config.Chain.TRX),
		PathReadAndDelete(config.Chain.ETH),
		PathReadAndDelete(config.Chain.BTC),
		PathReadAndDelete(config.Chain.TON),
		PathReadAndDelete(config.Chain.SOL),

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
