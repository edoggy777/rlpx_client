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

# Makefile
make clean && make install

# Make gen-keys
make gen-keys

# Keys for Anvil if testing against geth then you will have to key that key
./rlpx_client -k test_privkey.bin -P geth_test_pubkey.bin -h 127.0.0.1 -p 30303
