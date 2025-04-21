package backend_test

import (
	"context"
	"testing"

	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteKeyManager_UsingHandlers(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	pathDelete := "key-managers/btc/svc/delete"
	pathCreate := "key-managers/btc/svc"

	// 1) Create first key with specific private key
	req1 := logical.TestRequest(t, logical.UpdateOperation, pathCreate)
	req1.Storage = storage
	req1.Data = map[string]interface{}{"private_key": "KzQJ9vR4JeoJicejXmdvjcoDmZHa665diNxt17o3KRw3Hvix5CA5"}
	resp1, err := b.HandleRequest(context.Background(), req1)
	require.NoError(t, err)
	addr1 := resp1.Data["address"].(string)

	// 2) Create second key (random)
	req2 := logical.TestRequest(t, logical.UpdateOperation, pathCreate)
	req2.Storage = storage
	req1.Data = map[string]interface{}{"rnd": "123"}
	resp2, err := b.HandleRequest(context.Background(), req2)
	require.NoError(t, err)
	addr2 := resp2.Data["address"].(string)

	// Verify two keys present
	reqList := logical.TestRequest(t, logical.ReadOperation, pathCreate)
	reqList.Storage = storage
	respList, err := b.HandleRequest(context.Background(), reqList)
	require.NoError(t, err)
	pairs := respList.Data["key_pairs"].([]map[string]string)
	require.Len(t, pairs, 2)

	// 3) Delete first address
	reqDel := logical.TestRequest(t, logical.DeleteOperation, pathDelete)
	reqDel.Storage = storage
	reqDel.Data = map[string]interface{}{"name": "svc", "address": addr1}
	respDel, err := b.HandleRequest(context.Background(), reqDel)
	require.NoError(t, err)
	assert.Nil(t, respDel)

	// Verify one remaining
	reqAfterDel := logical.TestRequest(t, logical.ReadOperation, pathCreate)
	reqAfterDel.Storage = storage
	respAfter, err := b.HandleRequest(context.Background(), reqAfterDel)
	require.NoError(t, err)
	remaining := respAfter.Data["key_pairs"].([]map[string]string)
	assert.Len(t, remaining, 1)
	remainingAddr := remaining[0]["address"]
	assert.Equal(t, addr2, remainingAddr)

	// 4) Delete last address
	reqDel2 := logical.TestRequest(t, logical.DeleteOperation, pathDelete)
	reqDel2.Storage = storage
	reqDel2.Data = map[string]interface{}{"name": "svc", "address": addr2}
	respDel2, err := b.HandleRequest(context.Background(), reqDel2)
	require.NoError(t, err)
	assert.Nil(t, respDel2)

	// Verify service removed
	reqFinal := logical.TestRequest(t, logical.ReadOperation, pathCreate)
	reqFinal.Storage = storage
	respFinal, err := b.HandleRequest(context.Background(), reqFinal)
	require.NoError(t, err)
	assert.Nil(t, respFinal.Data)
}
