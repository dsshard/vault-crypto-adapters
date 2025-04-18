package config

type ChainType string

var Chain = struct {
	BTC ChainType
	ETH ChainType
	TON ChainType
	TRX ChainType
	SOL ChainType
}{
	BTC: "btc",
	ETH: "eth",
	TON: "ton",
	TRX: "trx",
	SOL: "sol",
}
