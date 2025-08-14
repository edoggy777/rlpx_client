#ifndef AES_MAC_H
#define AES_MAC_H

#include <stdint.h>
#include <stddef.h>
#include "rlpx_handshake.h"

// AES-CTR encryption/decryption
int aes_ctr_encrypt(const rlpx_secrets_t* secrets, const uint8_t* plaintext, size_t len, uint8_t* ciphertext);
int aes_ctr_decrypt(const rlpx_secrets_t* secrets, const uint8_t* ciphertext, size_t len, uint8_t* plaintext);

// MAC calculation and verification
int calculate_frame_mac(const rlpx_secrets_t* secrets, const uint8_t* frame_data, size_t len, uint8_t mac[16]);
int verify_frame_mac(const rlpx_secrets_t* secrets, const uint8_t* header, size_t header_len, 
                     const uint8_t* frame_data, size_t frame_len);

#endif // AES_MAC_H
