package backend

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestPathExistenceCheck_NoEntry: Test the existence check for a path that does not exist
func TestPathExistenceCheck_NoEntry(t *testing.T) {
	ctx := context.Background()
	stg := &logical.InmemStorage{} // In‑memory storage :contentReference[oaicite:0]{index=0}
	req := &logical.Request{Storage: stg, Path: "foo/bar"}

	ok, err := PathExistenceCheck(ctx, req, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected existence=false for missing entry, got true")
	}
}
