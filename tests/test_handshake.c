#include "../src/rlpx_handshake.h"
#include "../src/ecies.h"
#include "../src/crypto_ec.h"
#include "../src/snappy.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void test_handshake_init() {
    rlpx_conn_t conn;
    assert(rlpx_init(&conn, NULL) == 0);     // random key
    assert(conn.state == RLPX_STATE_INIT);
    assert(conn.sockfd == -1);
    assert(conn.static_pubkey[0] == 0x04);
    printf("✓ Handshake initialization test passed\n");
}

void test_ecies_roundtrip() {
    uint8_t priv[32], pub[65];
    assert(ec_generate_keypair(priv, pub) == 0);
    uint8_t msg[] = "rlpx auth body";
    uint8_t aad[2] = {0x01, 0x02};
    uint8_t ct[256]; size_t ct_len = sizeof(ct);
    assert(ecies_encrypt(pub, msg, sizeof(msg), aad, 2, ct, &ct_len) == 0);
    assert(ct_len == ECIES_OVERHEAD + sizeof(msg));
    uint8_t pt[256]; size_t pt_len = sizeof(pt);
    assert(ecies_decrypt(priv, ct, ct_len, aad, 2, pt, &pt_len) == 0);
    assert(pt_len == sizeof(msg) && memcmp(pt, msg, pt_len) == 0);
    // wrong AAD must fail the MAC
    uint8_t bad[2] = {0x01, 0x03};
    pt_len = sizeof(pt);
    assert(ecies_decrypt(priv, ct, ct_len, bad, 2, pt, &pt_len) != 0);
    printf("✓ ECIES round-trip test passed\n");
}

void test_snappy_roundtrip() {
    uint8_t in[1000], out[2048], back[1000];
    for (int i = 0; i < 1000; i++) in[i] = (uint8_t)(i * 7);
    size_t c = snappy_compress(in, sizeof(in), out, sizeof(out));
    assert(c > 0);
    assert(snappy_uncompressed_length(out, c) == 1000);
    assert(snappy_uncompress(out, c, back, sizeof(back)) == 1000);
    assert(memcmp(in, back, 1000) == 0);
    // a real compressed block with a back-reference: "abababab" -> 08 00 'a' 'b' copy(len6,off2)
    uint8_t ref[] = {0x08, 0x04, 'a', 'b', 0x09, 0x02};
    assert(snappy_uncompress(ref, sizeof(ref), back, sizeof(back)) == 8);
    assert(memcmp(back, "abababab", 8) == 0);
    printf("✓ Snappy round-trip test passed\n");
}

void test_key_derivation() {
    rlpx_conn_t conn;
    assert(rlpx_init(&conn, NULL) == 0);
    uint8_t peer_priv[32];
    assert(ec_generate_keypair(conn.ephemeral_privkey, conn.ephemeral_pubkey) == 0);
    assert(ec_generate_keypair(peer_priv, conn.peer_ephemeral_pubkey) == 0);
    memset(conn.local_nonce, 1, 32);
    memset(conn.remote_nonce, 2, 32);
    conn.auth_packet_len = conn.ack_packet_len = 0;
    assert(rlpx_derive_secrets(&conn) == 0);
    int all_zero = 1;
    for (int i = 0; i < 32; i++) if (conn.secrets.aes_secret[i]) all_zero = 0;
    assert(!all_zero);
    assert(conn.egress_cipher && conn.ingress_cipher && conn.mac_cipher);
    rlpx_close(&conn);
    printf("✓ Key derivation test passed\n");
}

int main() {
    test_handshake_init();
    test_ecies_roundtrip();
    test_snappy_roundtrip();
    test_key_derivation();
    printf("All handshake tests passed!\n");
    return 0;
}
