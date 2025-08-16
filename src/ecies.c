// ecies.c
#include "ecies.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Concat / X9.63 KDF (SHA-256)
static int concat_kdf_sha256(const unsigned char *Z, size_t Z_len,
                             const unsigned char *info, size_t info_len,
                             unsigned char *out, size_t out_len) {
    uint32_t counter = 1;
    size_t generated = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    while (generated < out_len) {
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        unsigned char ctr[4] = {
            (unsigned char)((counter >> 24) & 0xff),
            (unsigned char)((counter >> 16) & 0xff),
            (unsigned char)((counter >>  8) & 0xff),
            (unsigned char)( counter        & 0xff)
        };
        SHA256_Update(&ctx, ctr, 4);
        SHA256_Update(&ctx, Z, Z_len);
        if (info && info_len) SHA256_Update(&ctx, info, info_len);
        SHA256_Final(hash, &ctx);

        size_t to_copy = (out_len - generated > sizeof(hash)) ? sizeof(hash) : (out_len - generated);
        memcpy(out + generated, hash, to_copy);
        generated += to_copy;
        counter++;
    }
    OPENSSL_cleanse(hash, sizeof(hash));
    return 1;
}

// ecies_encrypt:
// out: R(65) || IV(16) || C(plaintext_len) || TAG(32)
// caller must provide out_len with available buffer size; on success out_len is set to bytes written.
// aad should be the 2-byte big-endian length prefix for the wire (auth-size) when used for RLPx auth.
int ecies_encrypt(const uint8_t pubkey[65],
                  const uint8_t *plaintext, size_t plaintext_len,
                  const uint8_t *aad, size_t aad_len,
                  uint8_t *out, size_t *out_len)
{
    printf("DEBUG: Real ECIES encryption starting...\n");
    size_t needed = 65 + 16 + plaintext_len + 32;
    if (*out_len < needed) {
        printf("DEBUG: ECIES output buffer too small: %zu < %zu\n", *out_len, needed);
        return -1;
    }

    // ephemeral keypair - caller must link with crypto_ec; but we will generate ephemeral using OpenSSL RAND + caller ec pub? 
    // For simplicity we require caller supplies ephemeral generation function (but in this file we'll generate a keypair via libsecp256k1 through external API)
    // To avoid coupling, we require the application provide ephemeral priv/pub via crypto_ec functions.
    // But user prefed earlier ec_generate_keypair; we'll use it by declaring extern (weak coupling).
    extern int ec_generate_keypair(uint8_t privkey[32], uint8_t pubkey[65]);
    extern int ec_ecdh(const uint8_t privkey[32], const uint8_t pubkey[65], uint8_t shared[32]);

    uint8_t eph_priv[32], eph_pub[65];
    if (ec_generate_keypair(eph_priv, eph_pub) != 0) {
        printf("DEBUG: ECIES ephemeral key generation failed\n");
        return -1;
    }

    // ECDH X coordinate Z (32 bytes)
    uint8_t Z[32];
    if (ec_ecdh(eph_priv, pubkey, Z) != 0) {
        printf("DEBUG: ECIES ECDH failed\n");
        return -1;
    }

    // KDF: produce 32 bytes -> kE(16) | kM(16)
    unsigned char kmat[32];
    if (!concat_kdf_sha256(Z, 32, NULL, 0, kmat, sizeof(kmat))) {
        printf("DEBUG: KDF failed\n");
        return -1;
    }
    unsigned char *kE = kmat;
    unsigned char *kM = kmat + 16;

    // random IV 16 bytes
    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        printf("DEBUG: RAND_bytes failed\n");
        OPENSSL_cleanse(kmat, sizeof(kmat));
        return -1;
    }

    // AES-128-CTR encrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(kmat, sizeof(kmat));
        return -1;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, kE, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(kmat, sizeof(kmat));
        return -1;
    }

    uint8_t *p = out;
    memcpy(p, eph_pub, 65); p += 65;
    memcpy(p, iv, 16); p += 16;

    int outl = 0, outf = 0;
    if (EVP_EncryptUpdate(ctx, p, &outl, plaintext, (int)plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(kmat, sizeof(kmat));
        return -1;
    }
    if (EVP_EncryptFinal_ex(ctx, p + outl, &outf) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(kmat, sizeof(kmat));
        return -1;
    }
    size_t c_len = (size_t)(outl + outf);
    p += c_len;
    EVP_CIPHER_CTX_free(ctx);

    // HMAC-SHA256 keyed by SHA256(kM), input = AAD || IV || C
    unsigned char mac_key32[32];
    SHA256(kM, 16, mac_key32);

    unsigned char tag[32];
    unsigned int taglen = 0;
    HMAC_CTX *h = HMAC_CTX_new();
    if (!h) {
        OPENSSL_cleanse(kmat, sizeof(kmat));
        OPENSSL_cleanse(mac_key32, sizeof(mac_key32));
        return -1;
    }
    HMAC_Init_ex(h, mac_key32, sizeof(mac_key32), EVP_sha256(), NULL);
    if (aad && aad_len) HMAC_Update(h, aad, aad_len);
    HMAC_Update(h, iv, sizeof(iv));
    // ciphertext is at out + 65 + 16
    HMAC_Update(h, out + 65 + 16, c_len);
    HMAC_Final(h, tag, &taglen);
    HMAC_CTX_free(h);

    memcpy(p, tag, 32);
    p += 32;

    *out_len = (size_t)(p - out);

    // cleanse temporary secrets
    OPENSSL_cleanse(kmat, sizeof(kmat));
    OPENSSL_cleanse(mac_key32, sizeof(mac_key32));
    OPENSSL_cleanse(Z, sizeof(Z));
    OPENSSL_cleanse(eph_priv, sizeof(eph_priv));

    printf("DEBUG: ECIES encryption completed, out_len=%zu\n", *out_len);
    return 0;
}

int ecies_decrypt(const uint8_t privkey[32],
                  const uint8_t *in, size_t in_len,
                  const uint8_t *aad, size_t aad_len,
                  uint8_t *plaintext, size_t *plaintext_len)
{
    printf("DEBUG: Real ECIES decryption starting...\n");
    if (in_len < 65 + 16 + 32) {
        printf("DEBUG: ECIES ciphertext too short: %zu\n", in_len);
        return -1;
    }

    const uint8_t *R = in;
    const uint8_t *iv = in + 65;
    const uint8_t *C = in + 65 + 16;
    size_t c_len = in_len - (65 + 16 + 32);
    const uint8_t *tag = in + 65 + 16 + c_len;

    // ECDH
    extern int ec_ecdh(const uint8_t privkey[32], const uint8_t pubkey[65], uint8_t shared[32]);
    uint8_t Z[32];
    if (ec_ecdh(privkey, R, Z) != 0) {
        printf("DEBUG: ECIES ECDH failed\n");
        return -1;
    }

    unsigned char kmat[32];
    if (!concat_kdf_sha256(Z, 32, NULL, 0, kmat, sizeof(kmat))) {
        printf("DEBUG: KDF failed\n");
        return -1;
    }
    unsigned char *kE = kmat;
    unsigned char *kM = kmat + 16;

    // recompute HMAC
    unsigned char mac_key32[32];
    SHA256(kM, 16, mac_key32);

    unsigned char tag_calc[32];
    unsigned int taglen = 0;
    HMAC_CTX *h = HMAC_CTX_new();
    if (!h) {
        OPENSSL_cleanse(kmat, sizeof(kmat));
        return -1;
    }
    HMAC_Init_ex(h, mac_key32, sizeof(mac_key32), EVP_sha256(), NULL);
    if (aad && aad_len) HMAC_Update(h, aad, aad_len);
    HMAC_Update(h, iv, 16);
    HMAC_Update(h, C, c_len);
    HMAC_Final(h, tag_calc, &taglen);
    HMAC_CTX_free(h);

    if (CRYPTO_memcmp(tag_calc, tag, 32) != 0) {
        printf("DEBUG: ECIES MAC mismatch\n");
        OPENSSL_cleanse(kmat, sizeof(kmat));
        OPENSSL_cleanse(mac_key32, sizeof(mac_key32));
        return -1;
    }

    // AES-128-CTR decrypt
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        OPENSSL_cleanse(kmat, sizeof(kmat));
        OPENSSL_cleanse(mac_key32, sizeof(mac_key32));
        return -1;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, kE, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(kmat, sizeof(kmat));
        OPENSSL_cleanse(mac_key32, sizeof(mac_key32));
        return -1;
    }
    if (*plaintext_len < c_len) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(kmat, sizeof(kmat));
        OPENSSL_cleanse(mac_key32, sizeof(mac_key32));
        return -1;
    }
    int outl = 0, outf = 0;
    if (EVP_DecryptUpdate(ctx, plaintext, &outl, C, (int)c_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(kmat, sizeof(kmat));
        OPENSSL_cleanse(mac_key32, sizeof(mac_key32));
        return -1;
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext + outl, &outf) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(kmat, sizeof(kmat));
        OPENSSL_cleanse(mac_key32, sizeof(mac_key32));
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);

    *plaintext_len = (size_t)(outl + outf);

    OPENSSL_cleanse(kmat, sizeof(kmat));
    OPENSSL_cleanse(mac_key32, sizeof(mac_key32));
    OPENSSL_cleanse(Z, sizeof(Z));
    return 0;
}

