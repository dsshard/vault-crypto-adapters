# Vault Crypto-Adapters Plugin

A Vault secret engine plugin that enables you to **generate addresses** and **sign transactions** for multiple blockchains: Bitcoin, Ethereum, Solana, TON, Tron, XRP, and Dogecoin. All operations are exposed via Vault's standard REST API.

![Blockchain Support](https://img.shields.io/badge/Blockchains-7-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview

This plugin extends HashiCorp Vault to serve as a secure key management system for blockchain operations:

- **Secure key generation** - Create new blockchain addresses with keys never exposed outside Vault
- **Private key management** - Store and protect private keys in Vault's encrypted storage
- **Transaction signing** - Sign blockchain transactions without exposing private keys
- **Multi-chain support** - Single API interface for 7 leading blockchains
- **Optional key import** - Import existing keys when needed, but secure generation is recommended

## Installation

1. **Build the plugin** and place the binary in your Vault plugin directory.
2. **Register** it with Vault:
   ```sh
   vault plugin register -sha256=$(shasum -a 256 vault-crypto-adapters | awk '{print $1}') \
     -command="vault-crypto-adapters" \
     secret vault-crypto-adapters
   ```
3. **Enable the secret engine**:
   ```sh
   vault secrets enable -path=crypto-adapter \
     -description="Vault Crypto Adapters" \
     vault-crypto-adapters
   ```

## Supported Blockchains

| Chain    | Path Prefix         | Private Key Format            | Address Format                      |
|----------|---------------------|-------------------------------|-------------------------------------|
| Bitcoin  | `key-managers/btc`  | WIF or 32‑byte hex            | Bech32 (starts with `bc1…`)         |
| Ethereum | `key-managers/eth`  | 32‑byte hex                   | EIP‑55 checksummed (0x…)            |
| Solana   | `key-managers/sol`  | 64‑hex ed25519 seed or base58 | Base58 (44 chars)                   |
| TON      | `key-managers/ton`  | 32‑byte hex                   | URL‑safe base64 (~48 chars)         |
| Tron     | `key-managers/trx`  | 32‑byte secp256k1 hex         | Base58Check (34 chars, starts w/ T) |
| XRP      | `key-managers/xrp`  | 32‑byte hex                   | Base58 (starts with r)              |
| Dogecoin | `key-managers/doge` | WIF or 32‑byte hex            | Base58Check (starts with D/A/9)     |

## API Reference

### 1. Create / Import a Key

Creates a new key pair or imports an existing private key for a specified blockchain.

**Endpoint**: `POST /v1/key-managers/{chain}`

**Request Body (JSON)**:
- `serviceName` (string, required) — Logical service identifier
- `privateKey` (string, optional) — Private key in the format specified in the table above. **If omitted, a new secure key is automatically generated**
- `external_data` (object, optional) — Arbitrary metadata to attach to this key pair
- `lock` (boolean, optional, default: false) — Lock the key

**Response (200 OK)**:
```json
{
  "data": {
    "service_name": "myservice",
    "address": "blockchain-specific-address",
    "public_key": "public-key-hex"
  }
}
```

**Examples**:
```bash
# RECOMMENDED: Generate a new random key securely within Vault
curl -X POST $VAULT_ADDR/v1/key-managers/eth \
-H "X-Vault-Token: $VAULT_TOKEN" \
-d '{"serviceName":"myservice"}'

# ALTERNATIVE: Import an existing private key
curl -X POST $VAULT_ADDR/v1/key-managers/eth \
-H "X-Vault-Token: $VAULT_TOKEN" \
-d '{"serviceName":"myservice","privateKey":"4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7"}'
```

### 2. List Services

Lists all services registered for a specific blockchain.

**Endpoint**: `LIST /v1/key-managers/{chain}`

**Response (200 OK)**:
```json
{
  "data": {
    "keys": ["myservice", "anotherService"]
  }
}
```

**Example**:
```bash
curl -X LIST $VAULT_ADDR/v1/key-managers/btc \
-H "X-Vault-Token: $VAULT_TOKEN"
```

### 3. Read Service Details

Retrieves all addresses associated with a service for a specific blockchain.

**Endpoint**: `GET /v1/key-managers/{chain}/{serviceName}`

**Response (200 OK)**:
```json
{
  "data": {
    "service_name": "myservice",
    "key_pairs": [
      {
        "address": "blockchain-address-1",
        "public_key": "public-key-hex-1",
        "external_data": {
          "meta": "optional-metadata"
        }
      },
      {
        "address": "blockchain-address-2",
        "public_key": "public-key-hex-2"
      }
    ]
  }
}
```

**Example**:
```bash
curl -X GET $VAULT_ADDR/v1/key-managers/eth/myservice \
-H "X-Vault-Token: $VAULT_TOKEN"
```

### 4. Update External Data

Updates metadata associated with a specific address.

**Endpoint**: `POST /v1/key-managers/{chain}/{serviceName}/external`

**Request Body (JSON)**:
- `address` (string, required) — Blockchain address
- `external_data` (object, required) — Metadata to update
- `lock` (boolean, optional, default: false) — Lock the external data from further updates

**Response (200 OK)**:
```json
{
  "data": {
    "status": "external_data_updated",
    "address": "blockchain-address"
  }
}
```

**Example**:
```bash
curl -X POST $VAULT_ADDR/v1/key-managers/eth/myservice/external \
-H "X-Vault-Token: $VAULT_TOKEN" \
-d '{"address":"0x1234...","external_data":{"description":"Main account"}}'
```

### 5. Sign Transaction/Hash

Signs a transaction hash using a private key stored in the vault.

**Endpoint**: `POST /v1/key-managers/{chain}/{serviceName}/sign`

**Request Body (JSON)**:
- `name` (string, required) — Service name
- `hash` (string, required) — Hex-encoded hash/data to sign
- `address` (string, required) — The blockchain address to use for signing

**Response (200 OK)**:
```json
{
  "data": {
    "signature": "hex-encoded-signature"
  }
}
```

**Example**:
```bash
curl -X POST $VAULT_ADDR/v1/key-managers/eth/myservice/sign \
-H "X-Vault-Token: $VAULT_TOKEN" \
-d '{"hash":"1234abcd...","address":"0x1234..."}'
```

### 6. Delete Address

Removes a specific address from a service.

**Endpoint**: `DELETE /v1/key-managers/{chain}/{serviceName}`

**Request Body (JSON)**:
- `name` (string, required) — Service name
- `address` (string, required) — The blockchain address to delete

**Response (204 No Content)**

**Example**:
```bash
curl -X DELETE $VAULT_ADDR/v1/key-managers/eth/myservice \
-H "X-Vault-Token: $VAULT_TOKEN" \
-d '{"name":"myservice","address":"0x1234..."}'
```

## Blockchain-Specific Examples

### Key Generation vs Key Import

One of the **main security features** of this plugin is the ability to generate keys securely within Vault without ever exposing private keys:

```bash
# RECOMMENDED: Generate a new random key (no privateKey required)
vault write key-managers/eth serviceName=secure-wallet

# ALTERNATIVE: Import an existing private key (less secure)
vault write key-managers/eth serviceName=imported-wallet privateKey=4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7
```

### Bitcoin (BTC)

```bash
# Generate a new Bitcoin address with secure key generation
vault write key-managers/btc serviceName=mybtc
# Response shows: { "address": "bc1q...", "public_key": "02..." }

# Alternatively, import existing WIF private key
vault write key-managers/btc serviceName=imported-btc privateKey=L1aW4aubDFB7yfras2S1mN3bqg9...

# Sign a transaction hash (returns schnorr signature)
vault write key-managers/btc/mybtc/sign hash=deadbeef... address=bc1...
```

### Ethereum (ETH)

```bash
# Generate a new Ethereum address securely in vault
vault write key-managers/eth serviceName=myeth
# Response shows: { "address": "0x...", "public_key": "04..." }

# Alternatively, import existing private key
vault write key-managers/eth serviceName=imported-eth privateKey=4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7

# Sign a transaction hash (returns r|s|v signature)
vault write key-managers/eth/myeth/sign hash=deadbeef... address=0x...
```

### Solana (SOL)

```bash
# Generate a new Solana address with secure key generation
vault write key-managers/sol serviceName=mysol
# Response shows: { "address": "HqwjY...", "public_key": "HqwjY..." }

# Alternatively, import existing ed25519 seed
vault write key-managers/sol serviceName=imported-sol privateKey=3b6a27bccebfb65a6d8c3e78bf84df3e7a32b29b77b680f7f245d3c5f5b0a1b2

# Sign a message (returns ed25519 signature)
vault write key-managers/sol/mysol/sign hash=deadbeef... address=HqwjY...
```

### TON

```bash
# Generate a new TON address securely in vault
vault write key-managers/ton serviceName=myton
# Response shows: { "address": "EQB...", "public_key": "04..." }

# Alternatively, import existing private key
vault write key-managers/ton serviceName=imported-ton privateKey=4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7

# Sign a hash (returns ed25519 signature)
vault write key-managers/ton/myton/sign hash=b5ee9c7241... address=EQB2trRS...
```

### Tron (TRX)

```bash
# Generate a new TRON address securely in vault
vault write key-managers/trx serviceName=mytrx
# Response shows: { "address": "T...", "public_key": "04..." }

# Alternatively, import existing secp256k1 hex
vault write key-managers/trx serviceName=imported-trx privateKey=4c0883a69102937a9280f1222f7c9b6645e1a3c7bf2e5b4cd0bd58d7f9f5d9b7

# Sign a transaction hash (returns secp256k1 signature)
vault write key-managers/trx/mytrx/sign hash=deadbeef... address=T...
```

### XRP (Ripple)

```bash
# Generate a new XRP address securely in vault
vault write key-managers/xrp serviceName=myxrp
# Response shows: { "address": "r...", "public_key": "02..." }

# Alternatively, import existing private key
vault write key-managers/xrp serviceName=imported-xrp privateKey=90dc3e2382d825f290148356dbbe315135dc0fe60bb17030edd2ea6127f938d5

# Sign a transaction blob (returns DER-encoded signature)
vault write key-managers/xrp/myxrp/sign hash=deadbeef... address=r...
```

### Dogecoin (DOGE)

```bash
# Generate a new Dogecoin address securely in vault
vault write key-managers/doge serviceName=mydoge
# Response shows: { "address": "D...", "public_key": "02..." }

# Alternatively, import existing WIF or hex seed
vault write key-managers/doge serviceName=imported-doge privateKey=KzQJ9vR4JeoJicejXmdvjcoDmZHa665diNxt17o3KRw3Hvix5CA5

# Sign a hash (returns DER-encoded signature)
vault write key-managers/doge/mydoge/sign hash=deadbeef... address=D...
```

## Error Handling

- **400 Bad Request** — Missing required parameters or invalid input
- **404 Not Found** — Service or address not found

## Security Considerations

1. **Access Control** — Use Vault's policy system to restrict access to specific endpoints
2. **Audit Logs** — Enable Vault's audit device to log all key operations
3. **Key Rotation** — Consider implementing key rotation policies
4. **Seal/Unseal** — Ensure proper seal/unseal procedures to protect keys at rest

## Development

```bash
# Build the plugin
make build

# Run tests
make test

# Build release binary for Linux
make build-linux-release
```

This plugin is built with:
- Go 1.24
- HashiCorp Vault SDK v0.15.2
- Chain-specific SDKs for each blockchain