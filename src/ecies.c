// Add to src/ecies.c (new file)
#include "rlpx_handshake.h"
#include "crypto_ec.h"
#include "keccak.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Ethereum ECIES implementation
// Format: [ephemeral_pubkey_65_bytes][encrypted_data][mac_32_bytes]

int ecies_encrypt(const uint8_t pubkey[65], const uint8_t* plaintext, size_t plaintext_len, 
                  uint8_t* ciphertext, size_t* ciphertext_len) {
    printf("DEBUG: Real ECIES encryption starting...\n");
    
    // Calculate required output size: 65 (ephemeral pubkey) + plaintext_len + 32 (MAC)
    size_t required_len = 65 + plaintext_len + 32;
    if (*ciphertext_len < required_len) {
        printf("DEBUG: ECIES output buffer too small: %zu < %zu\n", *ciphertext_len, required_len);
        return -1;
    }
    
    // 1. Generate ephemeral keypair
    uint8_t ephemeral_privkey[32];
    uint8_t ephemeral_pubkey[65];
    if (ec_generate_keypair(ephemeral_privkey, ephemeral_pubkey) != 0) {
        printf("DEBUG: ECIES ephemeral key generation failed\n");
        return -1;
    }
    
    // 2. Compute shared secret using ECDH
    uint8_t shared_secret[32];
    if (ec_ecdh(ephemeral_privkey, pubkey, shared_secret) != 0) {
        printf("DEBUG: ECIES ECDH failed\n");
        return -1;
    }
    
    // 3. Derive encryption and MAC keys using KDF
    // Ethereum uses: keccak256(shared_secret || 0x00000001) for encryption key
    // keccak256(shared_secret || 0x00000002) for MAC key
    uint8_t kdf_input[36]; // 32 + 4
    memcpy(kdf_input, shared_secret, 32);
    
    // Derive encryption key
    uint32_t counter = 0x00000001;
    memcpy(kdf_input + 32, &counter, 4);
    uint8_t enc_key[32];
    keccak256(kdf_input, 36, enc_key);
    
    // Derive MAC key  
    counter = 0x00000002;
    memcpy(kdf_input + 32, &counter, 4);
    uint8_t mac_key[32];
    keccak256(kdf_input, 36, mac_key);
    
    printf("DEBUG: ECIES keys derived\n");
    
    // 4. Encrypt plaintext using AES-128-CTR
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("DEBUG: ECIES AES context creation failed\n");
        return -1;
    }
    
    // Use first 16 bytes of enc_key for AES-128
    uint8_t iv[16] = {0}; // Zero IV for CTR mode
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, enc_key, iv) != 1) {
        printf("DEBUG: ECIES AES init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Copy ephemeral public key to output
    memcpy(ciphertext, ephemeral_pubkey, 65);
    
    // Encrypt the plaintext
    int encrypted_len;
    if (EVP_EncryptUpdate(ctx, ciphertext + 65, &encrypted_len, plaintext, plaintext_len) != 1) {
        printf("DEBUG: ECIES AES encryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + 65 + encrypted_len, &final_len) != 1) {
        printf("DEBUG: ECIES AES finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    printf("DEBUG: ECIES AES encryption completed, encrypted_len: %d\n", encrypted_len);
    
    // 5. Calculate MAC over ephemeral_pubkey + encrypted_data
    size_t mac_input_len = 65 + plaintext_len;
    uint8_t mac_hash[32];
    
    unsigned int hmac_len = 32;
    if (HMAC(EVP_sha256(), mac_key, 32, ciphertext, mac_input_len, mac_hash, &hmac_len) == NULL) {
        printf("DEBUG: ECIES MAC calculation failed\n");
        return -1;
    }
    
    // Copy MAC to output
    memcpy(ciphertext + 65 + plaintext_len, mac_hash, 32);
    
    *ciphertext_len = required_len;
    printf("DEBUG: ECIES encryption completed successfully, output length: %zu\n", *ciphertext_len);
    
    return 0;
}

int ecies_decrypt(const uint8_t privkey[32], const uint8_t* ciphertext, size_t ciphertext_len,
                  uint8_t* plaintext, size_t* plaintext_len) {
    printf("DEBUG: Real ECIES decryption starting...\n");
    
    // Minimum size: 65 (ephemeral pubkey) + 32 (MAC) = 97 bytes
    if (ciphertext_len < 97) {
        printf("DEBUG: ECIES ciphertext too short: %zu\n", ciphertext_len);
        return -1;
    }
    
    size_t encrypted_data_len = ciphertext_len - 65 - 32;
    if (*plaintext_len < encrypted_data_len) {
        printf("DEBUG: ECIES plaintext buffer too small: %zu < %zu\n", *plaintext_len, encrypted_data_len);
        return -1;
    }
    
    // 1. Extract ephemeral public key
    const uint8_t* ephemeral_pubkey = ciphertext;
    const uint8_t* encrypted_data = ciphertext + 65;
    const uint8_t* received_mac = ciphertext + 65 + encrypted_data_len;
    
    // 2. Compute shared secret using ECDH
    uint8_t shared_secret[32];
    if (ec_ecdh(privkey, ephemeral_pubkey, shared_secret) != 0) {
        printf("DEBUG: ECIES ECDH decryption failed\n");
        return -1;
    }
    
    // 3. Derive encryption and MAC keys (same as encryption)
    uint8_t kdf_input[36];
    memcpy(kdf_input, shared_secret, 32);
    
    // Derive encryption key
    uint32_t counter = 0x00000001;
    memcpy(kdf_input + 32, &counter, 4);
    uint8_t enc_key[32];
    keccak256(kdf_input, 36, enc_key);
    
    // Derive MAC key
    counter = 0x00000002;
    memcpy(kdf_input + 32, &counter, 4);
    uint8_t mac_key[32];
    keccak256(kdf_input, 36, mac_key);
    
    // 4. Verify MAC
    uint8_t computed_mac[32];
    unsigned int hmac_len = 32;
    size_t mac_input_len = 65 + encrypted_data_len;
    
    if (HMAC(EVP_sha256(), mac_key, 32, ciphertext, mac_input_len, computed_mac, &hmac_len) == NULL) {
        printf("DEBUG: ECIES MAC computation failed\n");
        return -1;
    }
    
    // Constant-time MAC comparison
    int mac_valid = 1;
    for (int i = 0; i < 32; i++) {
        mac_valid &= (computed_mac[i] == received_mac[i]);
    }
    
    if (!mac_valid) {
        printf("DEBUG: ECIES MAC verification failed\n");
        return -1;
    }
    
    printf("DEBUG: ECIES MAC verification successful\n");
    
    // 5. Decrypt data using AES-128-CTR
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("DEBUG: ECIES AES context creation failed\n");
        return -1;
    }
    
    uint8_t iv[16] = {0}; // Zero IV for CTR mode
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, enc_key, iv) != 1) {
        printf("DEBUG: ECIES AES decrypt init failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int decrypted_len;
    if (EVP_DecryptUpdate(ctx, plaintext, &decrypted_len, encrypted_data, encrypted_data_len) != 1) {
        printf("DEBUG: ECIES AES decryption failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + decrypted_len, &final_len) != 1) {
        printf("DEBUG: ECIES AES finalization failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    *plaintext_len = decrypted_len + final_len;
    printf("DEBUG: ECIES decryption completed successfully, plaintext length: %zu\n", *plaintext_len);
    
    return 0;
}
