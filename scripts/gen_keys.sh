#!/bin/sh
# Generate a secp256k1 keypair for rlpx_client:
#   test_privkey.bin (32 raw bytes) and test_pubkey.bin (64 raw bytes, X||Y)
# Usage: scripts/gen_keys.sh [privkey_out] [pubkey_out]
set -e
PRIV="${1:-test_privkey.bin}"; PUB="${2:-test_pubkey.bin}"
openssl ecparam -name secp256k1 -genkey -noout 2>/dev/null \
  | openssl ec -text -noout 2>/dev/null | awk '
  /priv:/ {m="priv"; next} /pub:/ {m="pub"; next} /ASN1|NIST|Private|Public/ {m=""}
  m=="priv" {priv=priv $0} m=="pub" {pub=pub $0}
  END {gsub(/[: ]/,"",priv); gsub(/[: ]/,"",pub);
       print substr(priv, length(priv)-63) > "/tmp/rlpx_priv.hex";
       print substr(pub, 3) > "/tmp/rlpx_pub.hex"}'
python3 -c "import sys;open(sys.argv[2],'wb').write(bytes.fromhex(open(sys.argv[1]).read().strip()))" /tmp/rlpx_priv.hex "$PRIV"
python3 -c "import sys;open(sys.argv[2],'wb').write(bytes.fromhex(open(sys.argv[1]).read().strip()))" /tmp/rlpx_pub.hex "$PUB"
rm -f /tmp/rlpx_priv.hex /tmp/rlpx_pub.hex
echo "wrote $PRIV ($(wc -c < "$PRIV") bytes) and $PUB ($(wc -c < "$PUB") bytes)"
