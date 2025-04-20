package test

import (
	"context"
	"github.com/dsshard/vault-crypto-adapters/internal/backend"
	"github.com/dsshard/vault-crypto-adapters/internal/common"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
)

func NewTestBackend(t *testing.T) (*backend.Backend, logical.Storage) {
	t.Helper()
	storage := &logical.InmemStorage{}
	b, err := common.Factory(context.Background(), &logical.BackendConfig{
		StorageView: storage,
	})
	if err != nil {
		t.Fatalf("Factory error: %v", err)
	}
	be, ok := b.(*backend.Backend)
	if !ok {
		t.Fatalf("unexpected backend type: %T", b)
	}
	return be, storage
}
