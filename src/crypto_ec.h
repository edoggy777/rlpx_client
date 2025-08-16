#ifndef CRYPTO_EC_H
#define CRYPTO_EC_H

#include <stdint.h>
#include <secp256k1.h>

int ec_generate_keypair(uint8_t privkey[32], uint8_t pubkey[65]);
int ec_pubkey_from_privkey(const uint8_t privkey[32], uint8_t pubkey[65]);
int ec_ecdh(const uint8_t privkey[32], const uint8_t pubkey[65], uint8_t shared[32]);
int ec_sign(const uint8_t privkey[32], const uint8_t hash[32], uint8_t sig[64]);
int ec_sign_with_recid(const uint8_t privkey[32], const uint8_t hash[32], uint8_t sig_rs[64], int *recid_out);
int ec_verify(const uint8_t pubkey[65], const uint8_t hash[32], const uint8_t sig[64]);
int ec_recover_pubkey(const uint8_t sig_rs[64], int recid, const uint8_t hash[32], uint8_t out_pubkey[65]);
extern secp256k1_context* ctx;

#endif // CRYPTO_EC_H
