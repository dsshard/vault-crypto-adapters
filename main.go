package main

import (
	"github.com/dsshard/vault-crypto-adapters/internal/common"
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	err := flags.Parse(os.Args[1:])
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	err = plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: common.Factory,
	})

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
