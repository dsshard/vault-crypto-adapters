package backend_test

import (
	"context"
	"log"
	"testing"

	"github.com/dsshard/vault-crypto-adapters/internal/test"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteKeyManager_UsingHandlers(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	pathDelete := "key-managers/btc/svc"
	pathCreate := "key-managers/btc/svc"

	// 1) Create first key with specific private key
	req1 := logical.TestRequest(t, logical.CreateOperation, "key-managers/btc/svc")
	req1.Storage = storage
	req1.Data = map[string]interface{}{"private_key": "KzQJ9vR4JeoJicejXmdvjcoDmZHa665diNxt17o3KRw3Hvix5CA5"}
	resp1, err := b.HandleRequest(context.Background(), req1)
	require.NoError(t, err)
	addr1 := resp1.Data["address"].(string)

	// 2) Create second key (random)
	req2 := logical.TestRequest(t, logical.CreateOperation, pathCreate)
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
	pairs := respList.Data["key_pairs"].([]map[string]interface{})
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
	remaining := respAfter.Data["key_pairs"].([]map[string]interface{})
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

func TestListKeyManager_CheckList(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	pathList := "key-managers/btc"
	pathCreate1 := "key-managers/btc/test1"
	pathCreate2 := "key-managers/btc/test2"

	// 1) Create first key with specific private key
	req1 := logical.TestRequest(t, logical.CreateOperation, pathCreate1)
	req1.Storage = storage
	b.HandleRequest(context.Background(), req1)

	// 1) Create first key with specific private key
	req2 := logical.TestRequest(t, logical.CreateOperation, pathCreate2)
	req2.Storage = storage
	b.HandleRequest(context.Background(), req2)

	// 1) Create first key with specific private key
	req1111 := logical.TestRequest(t, logical.ListOperation, pathList)
	req1111.Storage = storage
	resp1111, err := b.HandleRequest(context.Background(), req1111)
	require.NoError(t, err)

	require.Len(t, resp1111.Data["keys"], 2)
}

func TestListKeyManager_CheckList_Eth(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	pathList := "key-managers/eth"
	pathCreate := "key-managers/eth/testeth"

	// Создаём eth/testeth
	reqCreate := logical.TestRequest(t, logical.CreateOperation, pathCreate)
	reqCreate.Storage = storage
	b.HandleRequest(context.Background(), reqCreate)

	// Листим eth
	reqList := logical.TestRequest(t, logical.ListOperation, pathList)
	reqList.Storage = storage
	resp, err := b.HandleRequest(context.Background(), reqList)
	require.NoError(t, err)
	require.Len(t, resp.Data["keys"], 1)
}

func TestUpdateExternalData(t *testing.T) {
	b, storage := test.NewTestBackend(t)
	pathCreate := "key-managers/btc/test"
	pathUpdate := "key-managers/btc/test/external"
	pathRead := "key-managers/btc/test"

	// 1. Создаём новый сервис
	reqCreate := logical.TestRequest(t, logical.CreateOperation, pathCreate)
	reqCreate.Storage = storage
	res, err := b.HandleRequest(context.Background(), reqCreate)
	require.NoError(t, err)
	addr := res.Data["address"].(string)
	log.Print(addr)

	// 3. Пишем external_data в KeyPair
	reqUpdate := logical.TestRequest(t, logical.UpdateOperation, pathUpdate)
	reqUpdate.Storage = storage
	reqUpdate.Data = map[string]interface{}{
		"address":       addr,
		"external_data": map[string]interface{}{"note": "hello world", "env": "test"},
	}
	respUpdate, err := b.HandleRequest(context.Background(), reqUpdate)
	require.NoError(t, err)
	require.NotNil(t, respUpdate)

	require.True(t, respUpdate.Data["status"] == "external_data_updated")

	// 4. Читаем и проверяем, что external_data появилось
	reqRead := logical.TestRequest(t, logical.ReadOperation, pathRead)
	reqRead.Storage = storage
	respRead, err := b.HandleRequest(context.Background(), reqRead)
	require.NoError(t, err)

	rawPairs, ok := respRead.Data["key_pairs"].([]map[string]interface{})
	require.True(t, ok)
	require.Len(t, rawPairs, 1)

	externalData, ok := rawPairs[0]["external_data"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "hello world", externalData["note"])
	require.Equal(t, "test", externalData["env"])

	// 5. Очищаем external_data
	reqClear := logical.TestRequest(t, logical.UpdateOperation, pathUpdate)
	reqClear.Storage = storage
	reqClear.Data = map[string]interface{}{
		"address": addr,
		// external_data нет => должно очиститься
	}
	respClear, err := b.HandleRequest(context.Background(), reqClear)
	require.NoError(t, err)
	require.NotNil(t, respClear)

	// 6. Читаем снова и проверяем, что external_data нет
	reqRead2 := logical.TestRequest(t, logical.ReadOperation, pathRead)
	reqRead2.Storage = storage
	respRead2, err := b.HandleRequest(context.Background(), reqRead2)
	require.NoError(t, err)

	rawPairs2, ok := respRead2.Data["key_pairs"].([]map[string]interface{})
	require.True(t, ok)
	require.Len(t, rawPairs2, 1)

	_, hasExternalData := rawPairs2[0]["external_data"]
	require.False(t, hasExternalData, "external_data should be removed")
}
