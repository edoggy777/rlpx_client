#ifndef ECIES_H
#define ECIES_H

#include <stdint.h>
#include <stddef.h>

int ecies_encrypt(const uint8_t pubkey[65], const uint8_t* plaintext, size_t plaintext_len, 
                  uint8_t* ciphertext, size_t* ciphertext_len);
int ecies_decrypt(const uint8_t privkey[32], const uint8_t* ciphertext, size_t ciphertext_len,
                  uint8_t* plaintext, size_t* plaintext_len);

#endif // ECIES_H
