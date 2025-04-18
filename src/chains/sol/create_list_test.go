package sol_test

import (
	"context"
	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestSolCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// Create two services under sol
	for _, svc := range []string{"svc1", "svc2"} {
		req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/sol")
		req.Storage = storage
		req.Data = map[string]interface{}{
			"serviceName": svc,
		}
		_, err := b.HandleRequest(context.Background(), req)
		require.NoError(t, err)
	}

	// List them
	req := logical.TestRequest(t, logical.ListOperation, "key-managers/sol")
	req.Storage = storage
	resp, err := b.HandleRequest(context.Background(), req)
	require.NoError(t, err)

	// keys come back under "keys"
	keys, ok := resp.Data["keys"].([]string)
	require.True(t, ok, "expected resp.Data[\"keys\"] to be []string")
	assert.ElementsMatch(t, []string{"svc1", "svc2"}, keys)
}
