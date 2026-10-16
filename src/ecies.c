// ecies.c - ECIES as used by RLPx (secp256k1, NIST SP 800-56 concat KDF,
// AES-128-CTR, HMAC-SHA256 keyed with sha256(kM)).
//
//   R(65) || iv(16) || c || d(32)
//   d = HMAC(sha256(kM), iv || c || shared-mac-data)
//
// shared-mac-data is the 2-byte big-endian size prefix of the auth/ack packet.
#include "ecies.h"
#include "crypto_ec.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>

// NIST SP 800-56 Concatenation KDF with SHA-256 (what geth's concatKDF does)
static int concat_kdf_sha256(const uint8_t* Z, size_t Z_len, uint8_t* out, size_t out_len) {
    uint32_t counter = 1;
    size_t generated = 0;
    while (generated < out_len) {
        uint8_t ctr[4] = { (uint8_t)(counter >> 24), (uint8_t)(counter >> 16),
                           (uint8_t)(counter >> 8),  (uint8_t)counter };
        uint8_t hash[32];
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        if (!md) return -1;
        unsigned int hl = 0;
        if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
            EVP_DigestUpdate(md, ctr, 4) != 1 ||
            EVP_DigestUpdate(md, Z, Z_len) != 1 ||
            EVP_DigestFinal_ex(md, hash, &hl) != 1) {
            EVP_MD_CTX_free(md);
            return -1;
        }
        EVP_MD_CTX_free(md);
        size_t n = out_len - generated < 32 ? out_len - generated : 32;
        memcpy(out + generated, hash, n);
        generated += n;
        counter++;
        OPENSSL_cleanse(hash, sizeof(hash));
    }
    return 0;
}

// tag = HMAC-SHA256(sha256(kM), iv || c || aad)
static int ecies_tag(const uint8_t kM[16], const uint8_t iv[16],
                     const uint8_t* c, size_t c_len,
                     const uint8_t* aad, size_t aad_len, uint8_t tag[32]) {
    uint8_t mac_key[32];
    unsigned int len = 0;
    if (!EVP_Digest(kM, 16, mac_key, &len, EVP_sha256(), NULL)) return -1;

    uint8_t* msg = OPENSSL_malloc(16 + c_len + aad_len);
    if (!msg) return -1;
    memcpy(msg, iv, 16);
    memcpy(msg + 16, c, c_len);
    if (aad_len) memcpy(msg + 16 + c_len, aad, aad_len);

    unsigned int tl = 0;
    unsigned char* r = HMAC(EVP_sha256(), mac_key, 32, msg, 16 + c_len + aad_len, tag, &tl);
    OPENSSL_free(msg);
    OPENSSL_cleanse(mac_key, sizeof(mac_key));
    return (r && tl == 32) ? 0 : -1;
}

static int aes128_ctr(const uint8_t key[16], const uint8_t iv[16],
                      const uint8_t* in, size_t len, uint8_t* out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int ok = 0, outl = 0, outf = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv) == 1 &&
        EVP_EncryptUpdate(ctx, out, &outl, in, (int)len) == 1 &&
        EVP_EncryptFinal_ex(ctx, out + outl, &outf) == 1 &&
        (size_t)(outl + outf) == len)
        ok = 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

int ecies_encrypt(const uint8_t pubkey[65],
                  const uint8_t* plaintext, size_t plaintext_len,
                  const uint8_t* aad, size_t aad_len,
                  uint8_t* out, size_t* out_len)
{
    size_t needed = ECIES_OVERHEAD + plaintext_len;
    if (*out_len < needed) return -1;

    uint8_t eph_priv[32], eph_pub[65], Z[32], kmat[32], iv[16];
    int rc = -1;

    if (ec_generate_keypair(eph_priv, eph_pub) != 0) goto done;
    if (ec_ecdh(eph_priv, pubkey, Z) != 0) goto done;
    if (concat_kdf_sha256(Z, 32, kmat, 32) != 0) goto done;
    if (RAND_bytes(iv, 16) != 1) goto done;

    memcpy(out, eph_pub, 65);
    memcpy(out + 65, iv, 16);
    if (aes128_ctr(kmat, iv, plaintext, plaintext_len, out + 65 + 16) != 0) goto done;
    if (ecies_tag(kmat + 16, iv, out + 65 + 16, plaintext_len, aad, aad_len,
                  out + 65 + 16 + plaintext_len) != 0) goto done;

    *out_len = needed;
    rc = 0;
done:
    OPENSSL_cleanse(eph_priv, sizeof(eph_priv));
    OPENSSL_cleanse(Z, sizeof(Z));
    OPENSSL_cleanse(kmat, sizeof(kmat));
    return rc;
}

int ecies_decrypt(const uint8_t privkey[32],
                  const uint8_t* in, size_t in_len,
                  const uint8_t* aad, size_t aad_len,
                  uint8_t* plaintext, size_t* plaintext_len)
{
    if (in_len < ECIES_OVERHEAD) return -1;
    const uint8_t* R = in;
    const uint8_t* iv = in + 65;
    const uint8_t* C = in + 65 + 16;
    size_t c_len = in_len - ECIES_OVERHEAD;
    const uint8_t* tag = C + c_len;
    if (*plaintext_len < c_len) return -1;

    uint8_t Z[32], kmat[32], tag_calc[32];
    int rc = -1;

    if (ec_ecdh(privkey, R, Z) != 0) goto done;
    if (concat_kdf_sha256(Z, 32, kmat, 32) != 0) goto done;
    if (ecies_tag(kmat + 16, iv, C, c_len, aad, aad_len, tag_calc) != 0) goto done;
    if (CRYPTO_memcmp(tag_calc, tag, 32) != 0) {
        fprintf(stderr, "ecies: MAC mismatch\n");
        goto done;
    }
    if (aes128_ctr(kmat, iv, C, c_len, plaintext) != 0) goto done;
    *plaintext_len = c_len;
    rc = 0;
done:
    OPENSSL_cleanse(Z, sizeof(Z));
    OPENSSL_cleanse(kmat, sizeof(kmat));
    return rc;
}
