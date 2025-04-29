package main

import (
	"testing"

	"github.com/hashicorp/vault/api"
)

func TestFlagSet_Parse_NoArgs(t *testing.T) {
	meta := &api.PluginAPIClientMeta{}
	flags := meta.FlagSet()
	if err := flags.Parse([]string{}); err != nil {
		t.Fatalf("expected that parsing an empty list of arguments would not return an error, but instead we got: %v", err)
	}
}

func TestGetTLSConfig_NotNil(t *testing.T) {
	meta := &api.PluginAPIClientMeta{}
	flags := meta.FlagSet()
	if err := flags.Parse([]string{}); err != nil {
		t.Fatalf("expected no error when parsing no args, got %v", err)
	}
}
