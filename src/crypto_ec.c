#include "crypto_ec.h"
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <string.h>

static secp256k1_context* ctx = NULL;

static void init_secp256k1() {
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
}

int ec_generate_keypair(uint8_t privkey[32], uint8_t pubkey[65]) {
    init_secp256k1();
    
    // Generate random private key (should use secure random in practice)
    // For now, placeholder - implement proper random generation
    memset(privkey, 0x42, 32); // PLACEHOLDER!
    
    return ec_pubkey_from_privkey(privkey, pubkey);
}

int ec_pubkey_from_privkey(const uint8_t privkey[32], uint8_t pubkey[65]) {
    init_secp256k1();
    
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, privkey)) {
        return -1;
    }
    
    size_t pubkey_len = 65;
    if (!secp256k1_ec_pubkey_serialize(ctx, pubkey, &pubkey_len, &pub, SECP256K1_EC_UNCOMPRESSED)) {
        return -1;
    }
    
    return 0;
}

int ec_ecdh(const uint8_t privkey[32], const uint8_t pubkey[65], uint8_t shared[32]) {
    init_secp256k1();
    
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &pub, pubkey, 65)) {
        return -1;
    }
    
    if (!secp256k1_ecdh(ctx, shared, &pub, privkey, NULL, NULL)) {
        return -1;
    }
    
    return 0;
}

int ec_sign(const uint8_t privkey[32], const uint8_t hash[32], uint8_t sig[64]) {
    init_secp256k1();
    
    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_sign(ctx, &signature, hash, privkey, NULL, NULL)) {
        return -1;
    }
    
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, sig, &signature)) {
        return -1;
    }
    
    return 0;
}

int ec_verify(const uint8_t pubkey[65], const uint8_t hash[32], const uint8_t sig[64]) {
    init_secp256k1();
    
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &pub, pubkey, 65)) {
        return -1;
    }
    
    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &signature, sig)) {
        return -1;
    }
    
    return secp256k1_ecdsa_verify(ctx, &signature, hash, &pub) ? 0 : -1;
}
