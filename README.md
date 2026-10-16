## Support

If you find this project helpful, consider supporting it:

**Ethereum:** `0x0CDdCff8f61B45fB2870d8Bd46A2170Af62220A4`

[Donate with Ethereum](Eth:0x0CDdCff8f61B45fB2870d8Bd46A2170Af62220A4)

# Minimal RLPx Client in C

A minimal, external C implementation of the Ethereum devp2p RLPx protocol for testing, fuzzing, and research purposes.

## Features

- Complete RLPx handshake (Auth/AuthAck) with EIP-8 compatibility
- Symmetric key derivation following RLPx specification
- Encrypted frame sending/receiving with MAC verification
- Minimal RLP encoding/decoding for handshake messages
- Fuzzing harness for security testing
- No dependencies on existing Ethereum client code

## Building

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install libsecp256k1-dev libssl-dev build-essential

# Or use the Makefile helper
make install-deps

# Build the client, then run the unit tests
make clean && make
make test
```

If your distro has no `libsecp256k1-dev` package, build it from source
(`git clone https://github.com/bitcoin-core/secp256k1 && cd secp256k1 && ./autogen.sh && ./configure --enable-module-recovery --enable-module-ecdh && make && sudo make install && sudo ldconfig`).

## Usage

```bash
# Generate our own static key (optional - a random key is used if -k is omitted)
scripts/gen_keys.sh                      # writes test_privkey.bin + test_pubkey.bin

# Connect to a node. The peer key can be a 64-byte file, 128 hex chars, or an enode URL:
./rlpx_client -k test_privkey.bin -P geth_pubkey.bin -h 127.0.0.1 -p 30303
./rlpx_client -e enode://<128 hex>@127.0.0.1:30303

# After the Hello exchange, read N messages from the peer (default 2):
./rlpx_client -e enode://...  -n 3

# Send a custom message (hex payload) with a given message id after Hello:
./rlpx_client -e enode://... -i 0x10 -m f85044018180a0...

# Fuzz mode: valid frame with garbage RLP, then raw junk on the wire
./rlpx_client -e enode://... -f
```

A geth node's enode URL is printed at startup (`self=enode://...`) or via
`admin.nodeInfo.enode` in `geth attach`. Start geth with `--nodekeyhex <64 hex>` to get a stable key.

What the client does: EIP-8 auth/ack handshake, session secret derivation,
encrypted + MAC'd framing per the RLPx spec, then a p2p Hello advertising `eth/68`.
Snappy compression is enabled automatically when the peer speaks p2p v5+.
Pings are answered with Pong; the peer's eth Status is printed. (No eth Status
is sent back by default, so real nodes drop the session after their timeout.)

### Testing against a real geth node

```bash
# terminal 1: a local geth with a fixed node key (no discovery, no peers needed)
geth --nodiscover --maxpeers 5 --nodekeyhex a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1
# look for:  Started P2P networking  self="enode://<128 hex>@127.0.0.1:30303?discport=0"

# terminal 2: dial it (quote the URL because of the ?discport part)
./rlpx_client -e 'enode://<128 hex>@127.0.0.1:30303' -n 3
```

Expected output: `✓ RLPx handshake successful`, geth's Hello (`Geth/v1.x...`,
capabilities `eth/68 snap/1`), then `<- eth Status`. Geth will send a Disconnect
after its timeout because we don't answer the Status - that's normal.

### Testing without geth

`tests/peer.mjs` is a small listening node built on `@ethereumjs/devp2p`:

```bash
mkdir /tmp/peer && cd /tmp/peer
npm i @ethereumjs/devp2p @ethereumjs/util @ethereumjs/common
node /path/to/rlpx_client/tests/peer.mjs      # prints "peer node id: 0x..."
./rlpx_client -P <that id without 0x> -n 3
```

### Applying a patch from a release

If you got the fix as a `0001-*.patch` file instead of pulling from git:

```bash
git clone https://github.com/edoggy777/rlpx_client.git && cd rlpx_client
git am /path/to/0001-Fix-RLPx-implementation-so-it-completes-a-real-hands.patch
make clean && make && make test
```

### Tested against

The handshake, framing and Hello exchange were verified against
[`@ethereumjs/devp2p`](https://github.com/ethereumjs/ethereumjs-monorepo) acting as
a listening peer (`node peer.mjs` style script, see `tests/peer.mjs`).
