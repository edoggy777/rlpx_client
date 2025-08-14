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
    test_ecdh_consistency();
    printf("All crypto tests passed!\n");
    return 0;
}
