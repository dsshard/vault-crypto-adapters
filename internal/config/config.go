package config

type ChainType string

var Chain = struct {
	BTC  ChainType
	ETH  ChainType
	TON  ChainType
	TRX  ChainType
	SOL  ChainType
	XRP  ChainType
	DOGE ChainType
}{
	BTC:  "btc",
	ETH:  "eth",
	TON:  "ton",
	TRX:  "trx",
	SOL:  "sol",
	XRP:  "xrp",
	DOGE: "doge",
}

// AllChains — упорядоченный список всех поддерживаемых ChainType
var AllChains = []ChainType{
	Chain.BTC,
	Chain.ETH,
	Chain.TON,
	Chain.TRX,
	Chain.SOL,
	Chain.XRP,
	Chain.DOGE,
}
