// src/aes_mac.c - Fixed version
#include "aes_mac.h"
#include "keccak.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>
#include <stdlib.h>

int aes_ctr_encrypt(const rlpx_secrets_t* secrets, const uint8_t* plaintext, size_t len, uint8_t* ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    // Initialize CTR with zero IV (RLPx uses specific IV derivation)
    uint8_t iv_counter[16] = {0};
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, secrets->aes_secret, iv_counter) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int outlen;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int aes_ctr_decrypt(const rlpx_secrets_t* secrets, const uint8_t* ciphertext, size_t len, uint8_t* plaintext) {
    // CTR mode: decryption is same as encryption
    return aes_ctr_encrypt(secrets, ciphertext, len, plaintext);
}

int calculate_frame_mac(const rlpx_secrets_t* secrets, const uint8_t* frame_data, size_t len, uint8_t mac[16]) {
    // RLPx uses specific MAC construction - implement per spec
    uint8_t* mac_input = malloc(len + 32); // frame + mac_secret
    if (!mac_input) return -1;
    
    memcpy(mac_input, secrets->mac_secret, 32);
    memcpy(mac_input + 32, frame_data, len);
    
    uint8_t full_hash[32];
    keccak256(mac_input, len + 32, full_hash);
    
    // Take first 16 bytes as MAC
    memcpy(mac, full_hash, 16);
    
    free(mac_input);
    return 0;
}

int verify_frame_mac(const rlpx_secrets_t* secrets, const uint8_t* header, size_t header_len, 
                     const uint8_t* frame_data, size_t frame_len) {
    uint8_t calculated_mac[16];
    uint8_t received_mac[16];
    
    // Extract MAC from end of frame_data
    if (frame_len < 16) return 0; // Invalid frame
    memcpy(received_mac, frame_data + frame_len - 16, 16);
    
    // Calculate MAC for header + payload (without MAC)
    size_t mac_data_len = header_len + frame_len - 16;
    uint8_t* mac_data = malloc(mac_data_len);
    if (!mac_data) return 0;
    
    memcpy(mac_data, header, header_len);
    memcpy(mac_data + header_len, frame_data, frame_len - 16);
    
    int result = calculate_frame_mac(secrets, mac_data, mac_data_len, calculated_mac);
    free(mac_data);
    
    if (result != 0) return 0;
    
    // Constant-time compare
    int match = 1;
    for (int i = 0; i < 16; i++) {
        match &= (calculated_mac[i] == received_mac[i]);
    }
    
    return match;
}
