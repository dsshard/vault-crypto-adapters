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

		btc.PathCreateAndList(),
		btc.PathSign(),
		btc.PathTransfer(),

		eth.PathCreateAndList(),
		eth.PathSign(),
		eth.PathTransfer(),
		eth.PathTransferERC20(),

		ton.PathCreateAndList(),
		ton.PathSign(),
		ton.PathTransfer(),
		ton.PathTransferJetton(),

		trx.PathCreateAndList(),
		trx.PathSign(),
		trx.PathTransferTx(),
		trx.PathTRC20Transfer(),

		sol.PathTransferToken(),
		sol.PathCreateAndList(),
		sol.PathSignSol(),
		sol.PathTransferNativeSol(),
	}
}
