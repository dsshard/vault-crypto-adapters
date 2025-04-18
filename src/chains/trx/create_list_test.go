package trx_test

import (
	"context"
	"github.com/dsshard/vault-crypto-adapters/src/test"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestTrxCreateAndListKeyManagers(t *testing.T) {
	b, storage := test.NewTestBackend(t)

	// 1) Import specific private key
	req := logical.TestRequest(t, logical.UpdateOperation, "key-managers/trx")
	req.Storage = storage
	req.Data = map[string]interface{}{
		"serviceName": "svc",
		"privateKey":  "0000000000000000000000000000000000000000000000000000000000000001",
	}
	resp, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	addr1 := resp.Data["address"].(string)
	assert.Regexp(t, `^T[A-Za-z0-9]{33}$`, addr1)

	// 2) Generate second key
	req = logical.TestRequest(t, logical.UpdateOperation, "key-managers/trx")
	req.Storage = storage
	req.Data = map[string]interface{}{"serviceName": "svc"}
	_, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)

	// 3) List services
	req = logical.TestRequest(t, logical.ListOperation, "key-managers/trx")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	services := resp.Data["keys"].([]string)
	assert.Equal(t, []string{"svc"}, services)

	// 4) Read service and check two addresses
	req = logical.TestRequest(t, logical.ReadOperation, "key-managers/trx/svc")
	req.Storage = storage
	resp, err = b.HandleRequest(context.Background(), req)
	assert.NoError(t, err)
	addrs := resp.Data["addresses"].([]string)
	assert.Len(t, addrs, 2)
	assert.Contains(t, addrs, addr1)
}
