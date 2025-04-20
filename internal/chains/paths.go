package chains

import (
	"github.com/dsshard/vault-crypto-adapters/internal/chains/btc"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/eth"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/sol"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/ton"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/trx"
	"github.com/dsshard/vault-crypto-adapters/internal/chains/xrp"
	"github.com/hashicorp/vault/sdk/framework"
)

func Paths() []*framework.Path {
	return []*framework.Path{
		btc.PathCrud(),
		btc.PathSign(),

		eth.PathCrud(),
		eth.PathSign(),

		ton.PathCrud(),
		ton.PathSign(),

		trx.PathCrud(),
		trx.PathSign(),

		sol.PathCrud(),
		sol.PathSign(),

		xrp.PathCrud(),
		xrp.PathSign(),
	}
}
