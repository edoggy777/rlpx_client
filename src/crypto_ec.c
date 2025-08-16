// crypto_ec.c
#include "crypto_ec.h"
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>

secp256k1_context* ctx = NULL;

static void init_secp256k1(void) {
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
}

static int random_privkey(uint8_t priv[32]) {
    init_secp256k1();
    for (int i = 0; i < 10; ++i) {
        if (RAND_bytes(priv, 32) != 1) {
            fprintf(stderr, "RAND_bytes failed\n");
            return 0;
        }
        if (secp256k1_ec_seckey_verify(ctx, priv)) {
            return 1; // valid
        }
    }
    fprintf(stderr, "Failed to generate valid secp256k1 private key after 10 attempts\n");
    return 0;
}

int ec_generate_keypair(uint8_t privkey[32], uint8_t pubkey[65]) {
    init_secp256k1();
    if (!random_privkey(privkey))
        return -1;
    return ec_pubkey_from_privkey(privkey, pubkey);
}

int ec_pubkey_from_privkey(const uint8_t privkey[32], uint8_t pubkey[65]) {
    init_secp256k1();
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_create(ctx, &pub, privkey))
        return -1;
    size_t outlen = 65;
    if (!secp256k1_ec_pubkey_serialize(ctx, pubkey, &outlen, &pub, SECP256K1_EC_UNCOMPRESSED))
        return -1;
    return 0;
}

// custom ecdh hashfn: write raw X coordinate (32 bytes)
static int ecdh_raw_x(unsigned char* output, const unsigned char* x, const unsigned char* y, void* data) {
    (void)y;
    (void)data;
    memcpy(output, x, 32);
    return 1;
}

int ec_ecdh(const uint8_t privkey[32], const uint8_t pubkey_bytes[65], uint8_t shared[32]) {
    init_secp256k1();
    printf("DEBUG: ECDH with privkey: ");
    for (int i = 0; i < 32; i++) printf("%02x", privkey[i]);
    printf("\nDEBUG: Pubkey: ");
    for (int i = 0; i < 65; i++) printf("%02x", pubkey_bytes[i]);
    printf("\n");
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &pub, pubkey_bytes, 65)) {
        printf("DEBUG: secp256k1_ec_pubkey_parse failed\n");
        return -1;
    }
    if (!secp256k1_ecdh(ctx, shared, &pub, privkey, ecdh_raw_x, NULL)) {
        printf("DEBUG: secp256k1_ecdh failed\n");
        return -1;
    }
    printf("DEBUG: ECDH shared secret: ");
    for (int i = 0; i < 32; i++) printf("%02x", shared[i]);
    printf("\n");
    return 0;
}

int ec_sign(const uint8_t privkey[32], const uint8_t hash[32], uint8_t sig[64]) {
    init_secp256k1();
    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_sign(ctx, &signature, hash, privkey, NULL, NULL))
        return -1;
    if (!secp256k1_ecdsa_signature_serialize_compact(ctx, sig, &signature))
        return -1;
    return 0;
}

int ec_sign_with_recid(const uint8_t privkey[32], const uint8_t hash[32], uint8_t sig_rs[64], int *recid_out) {
    init_secp256k1();
    secp256k1_ecdsa_recoverable_signature sigrec;
    if (!secp256k1_ecdsa_sign_recoverable(ctx, &sigrec, hash, privkey, NULL, NULL))
        return -1;
    int recid = 0;
    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig_rs, &recid, &sigrec))
        return -1;
    if (recid_out) *recid_out = recid;
    return 0;
}

int ec_verify(const uint8_t pubkey[65], const uint8_t hash[32], const uint8_t sig[64]) {
    init_secp256k1();
    secp256k1_pubkey pub;
    if (!secp256k1_ec_pubkey_parse(ctx, &pub, pubkey, 65))
        return -1;
    secp256k1_ecdsa_signature signature;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &signature, sig))
        return -1;
    return secp256k1_ecdsa_verify(ctx, &signature, hash, &pub) ? 0 : -1;
}

int ec_recover_pubkey(const uint8_t sig_rs[64], int recid, const uint8_t hash[32], uint8_t out_pubkey[65]) {
    init_secp256k1();
    secp256k1_ecdsa_recoverable_signature sigrec;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sigrec, sig_rs, recid))
        return -1;
    secp256k1_pubkey pub;
    if (!secp256k1_ecdsa_recover(ctx, &pub, &sigrec, hash))
        return -1;
    size_t outlen = 65;
    if (!secp256k1_ec_pubkey_serialize(ctx, out_pubkey, &outlen, &pub, SECP256K1_EC_UNCOMPRESSED))
        return -1;
    return 0;
}

