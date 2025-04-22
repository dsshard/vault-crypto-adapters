package main

import (
	"github.com/dsshard/vault-crypto-adapters/internal/common"
	"log"
	"os"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	logFile, err := os.OpenFile("/tmp/plugin-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
	}

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()

	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Printf("Failed to parse flags: %v\n", err)
		os.Exit(1)
	}

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: common.Factory,
	}); err != nil {
		log.Printf("Plugin Serve failed: %v\n", err)
		os.Exit(1)
	}
}
