# Vault Crypto‑Adapters Plugin

A Vault secret engine plugin that lets you **generate addresses** and **sign transactions** for five blockchains: Bitcoin, Ethereum, Solana, TON and Tron. All operations are exposed via Vault’s standard REST API.

---

## Installation

1. **Build the plugin** and place the binary in your Vault plugin directory.
2. **Register** it with Vault:
   ```sh
   vault plugin register -sha256=$(shasum -a 256 vault-crypto-adapters | awk '{print $1}') \
     -command="vault-crypto-adapters" \
     secret vault-crypto-adapters
3. Enable the secret engine:
    ```sh
    vault secrets enable -path=crypto-adapter \
      -description="Vault Crypto Adapters" \
      vault-crypto-adapters
    ```
---

**Part 2: Supported Chains**
---

## Supported Chains

| Chain     | Path Prefix           | Private Key Format                                         | Address Format                                    |
|-----------|-----------------------|------------------------------------------------------------|---------------------------------------------------|
| Bitcoin   | `key-managers/btc`    | WIF or 32‑byte hex                                         | Bech32 (starts with `bc1…`)                       |
| Ethereum  | `key-managers/eth`    | 32‑byte hex                                                | EIP‑55 checksummed (0x…)                           |
| Solana    | `key-managers/sol`    | 64‑hex ed25519 seed or base58 seed                         | Base58 (44 chars)                                  |
| TON       | `key-managers/ton`    | 32‑byte hex                                                | URL‑safe base64 (~48 chars)                        |
| Tron      | `key-managers/trx`    | 32‑byte secp256k1 hex or empty                             | Base58Check (34 chars, starts with `T`)            |


---

## API Reference

### 1. Create / Import a Key

**Request Body (JSON):**
- `serviceName` (string, required) — your logical service identifier.  
- `privateKey` (string, optional) — supply your own key (format per table above). If omitted or invalid, a new key is generated.

**Success (200):**
```json
{
  "data": {
    "service_name": "svc",
    "address":      "<address>",
    "public_key":   "<public_key>"
  }
}
```

```
curl -X POST $VAULT_ADDR/v1/key-managers/eth \
-H "X-Vault-Token: $VAULT_TOKEN" \
-d '{"serviceName":"svc","privateKey":"4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7"}'
```

---

**Part 4: API Reference – List & Read**  
---

### 2. List Services

LIST /v1/key-managers/{chain}


**Success (200):**
```json
{
  "data": {
    "keys": ["svc", "anotherService", …]
  }
}
```


---

**Part 5: CLI Examples**  
---

## CLI Examples

```sh
# Bitcoin: import WIF or generate new
vault write key-managers/btc serviceName=svc privateKey=L1aW4aubDFB7yfras2S1mN3bqg9...

# Ethereum: import hex seed or generate new
vault write key-managers/eth serviceName=svc privateKey=4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7

# Solana: import ed25519 seed or generate new
vault write key-managers/sol serviceName=svc privateKey=3b6a27bccebfb65a6d8c3e78bf84df3e7a32b29b77b680f7f245d3c5f5b0a1b2

# TON: import 32‑byte hex or generate new
vault write key-managers/ton serviceName=svc privateKey=4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7

# Tron: import secp256k1 hex or generate new
vault write key-managers/trx serviceName=svc privateKey=4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7
```


---

**Part 6: Error Handling & Footnote**  
---

## Error Handling

- **400 Bad Request** — missing `serviceName` or invalid `privateKey`.  
- **404 Not Found** — requesting a non‑existent service on `GET /key-managers/{chain}/{serviceName}`.

> _This documentation is derived from automated tests that verify key creation, import, and address generation across all five supported chains._
