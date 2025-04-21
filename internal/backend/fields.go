package backend

import "github.com/hashicorp/vault/sdk/framework"

var DefaultCrudOperations = map[string]*framework.FieldSchema{
	"name":    {Type: framework.TypeString},
	"address": {Type: framework.TypeString},
	"private_key": {
		Type:        framework.TypeString,
		Description: "(Optional, default random key) Hex string for the private key",
		Default:     "",
	},
	"rnd": {
		Type:        framework.TypeString,
		Description: "(default random key) only for vault success operations",
		Default:     "",
	},
}

var DefaultSignOperation = map[string]*framework.FieldSchema{
	"name": {Type: framework.TypeString},
	"hash": {
		Type:        framework.TypeString,
		Description: "Hex string of the hash that should be signed.",
		Default:     "",
	},
	"address": {
		Type:        framework.TypeString,
		Description: "The address that belongs to a private key in the key-manager.",
	},
}

var DefaultHelpDescriptionCreateList = `
    POST - create a new keyManager
    GET - list all addresses
`

var DefaultHelpHelpSynopsisCreateList = "Create new key-manager with input private-key or random private-key & list all the key-managers maintained by the plugin backend."
