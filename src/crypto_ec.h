#ifndef CRYPTO_EC_H
#define CRYPTO_EC_H

#include <stdint.h>

int ec_generate_keypair(uint8_t privkey[32], uint8_t pubkey[65]);
int ec_ecdh(const uint8_t privkey[32], const uint8_t pubkey[65], uint8_t shared[32]);
int ec_sign(const uint8_t privkey[32], const uint8_t hash[32], uint8_t sig[64]);
int ec_verify(const uint8_t pubkey[65], const uint8_t hash[32], const uint8_t sig[64]);
int ec_pubkey_from_privkey(const uint8_t privkey[32], uint8_t pubkey[65]);

#endif // CRYPTO_EC_H
