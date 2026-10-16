#include "../src/crypto_ec.h"
#include "../src/keccak.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void test_keccak_known_vectors() {
    // Test against known Keccak-256 vectors
    uint8_t input[] = "hello world";
    uint8_t expected[32] = {
        0x47, 0x17, 0x32, 0x85, 0xa8, 0xd7, 0x34, 0x1e,
        0x5e, 0x97, 0x2f, 0xc6, 0x77, 0x28, 0x63, 0x84,
        0xf8, 0x02, 0xf8, 0xef, 0x42, 0xa5, 0xec, 0x5f,
        0x03, 0xbb, 0xfa, 0x25, 0x4c, 0xb0, 0x1f, 0xad
    };
    
    uint8_t output[32];
    keccak256(input, strlen((char*)input), output);
    
    assert(memcmp(output, expected, 32) == 0);
    printf("✓ Keccak-256 test vector passed\n");
}

void test_keccak_incremental() {
    // incremental API must match one-shot and digest must be non-destructive
    uint8_t data[300];
    for (int i = 0; i < 300; i++) data[i] = (uint8_t)i;
    uint8_t one[32], inc[32], again[32];
    keccak256(data, 300, one);
    keccak_ctx_t c;
    keccak_init(&c);
    keccak_update(&c, data, 100);
    keccak_update(&c, data + 100, 200);
    keccak_digest(&c, inc);
    keccak_digest(&c, again);
    assert(memcmp(one, inc, 32) == 0 && memcmp(inc, again, 32) == 0);
    // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    keccak256(data, 0, one);
    assert(one[0] == 0xc5 && one[1] == 0xd2 && one[31] == 0x70);
    printf("✓ Keccak incremental test passed\n");
}

void test_ecdh_consistency() {
    uint8_t alice_priv[32], alice_pub[65];
    uint8_t bob_priv[32], bob_pub[65];
    uint8_t shared1[32], shared2[32];
    
    ec_generate_keypair(alice_priv, alice_pub);
    ec_generate_keypair(bob_priv, bob_pub);
    
    ec_ecdh(alice_priv, bob_pub, shared1);
    ec_ecdh(bob_priv, alice_pub, shared2);
    
    assert(memcmp(shared1, shared2, 32) == 0);
    printf("✓ ECDH consistency test passed\n");
}

int main() {
    test_keccak_known_vectors();
    test_keccak_incremental();
    test_ecdh_consistency();
    printf("All crypto tests passed!\n");
    return 0;
}
