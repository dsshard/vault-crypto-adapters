package chains

import (
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/btc"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/eth"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/sol"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/ton"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/trx"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/xrp"
	"github.com/dsshard/vault-crypto-adapters/internal/config"
	"github.com/hashicorp/vault/sdk/framework"
)

func Paths() []*framework.Path {
	return []*framework.Path{
		backend.PathReadAndDelete(config.Chain.TRX),
		backend.PathReadAndDelete(config.Chain.ETH),
		backend.PathReadAndDelete(config.Chain.BTC),
		backend.PathReadAndDelete(config.Chain.TON),
		backend.PathReadAndDelete(config.Chain.SOL),
		backend.PathReadAndDelete(config.Chain.XRP),

		btc.PathCreateAndList(),
		btc.PathSign(),

		eth.PathCreateAndList(),
		eth.PathSign(),

		ton.PathCreateAndList(),
		ton.PathSign(),

		trx.PathCreateAndList(),
		trx.PathSign(),

		sol.PathCreateAndList(),
		sol.PathSign(),

		xrp.PathCreateAndList(),
		xrp.PathSign(),
	}
}
