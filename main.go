package main

import (
	"github.com/dsshard/vault-crypto-adapters/internal/common"
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func getTLSConfig(meta *api.PluginAPIClientMeta) *api.TLSConfig {
	cfg := meta.GetTLSConfig() // может вернуть nil :contentReference[oaicite:0]{index=0}
	if cfg == nil {
		return &api.TLSConfig{}
	}
	return cfg
}

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	err := flags.Parse(os.Args[1:])
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	tlsConfig := getTLSConfig(apiClientMeta)
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err = plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: common.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	})

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
