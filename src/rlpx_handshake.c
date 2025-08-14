// src/rlpx_handshake.c - Fixed version
#include "rlpx_handshake.h"
#include "crypto_ec.h"
#include "keccak.h"
#include "rlp.h"
#include "net.h"
#include <string.h>
#include <stdlib.h>

// Function prototypes
int ecies_encrypt(const uint8_t pubkey[65], const uint8_t* plaintext, size_t plaintext_len, 
                  uint8_t* ciphertext, size_t* ciphertext_len);
int ecies_decrypt(const uint8_t privkey[32], const uint8_t* ciphertext, size_t ciphertext_len,
                  uint8_t* plaintext, size_t* plaintext_len);

int rlpx_init(rlpx_conn_t* conn, const char* static_privkey_file) {
    (void)static_privkey_file; // Suppress unused parameter warning
    
    memset(conn, 0, sizeof(*conn));
    conn->state = RLPX_STATE_INIT;
    conn->sockfd = -1;
    
    // Load static private key from file (implement file loading)
    // For now, use a placeholder
    memset(conn->static_privkey, 0x42, 32); // PLACEHOLDER
    ec_pubkey_from_privkey(conn->static_privkey, conn->static_pubkey);
    
    return 0;
}

int rlpx_create_auth(rlpx_conn_t* conn, uint8_t* auth_msg, size_t* auth_len) {
    // 1. Generate ephemeral keypair
    if (ec_generate_keypair(conn->ephemeral_privkey, conn->ephemeral_pubkey) != 0) {
        return -1;
    }
    
    // 2. Generate random nonce (implement proper random generation)
    for (int i = 0; i < 32; i++) {
        conn->local_nonce[i] = rand() & 0xff; // PLACEHOLDER - use secure random
    }
    
    // 3. Create signature of (shared-secret ^ nonce)
    uint8_t shared_secret[32];
    if (ec_ecdh(conn->static_privkey, conn->peer_static_pubkey, shared_secret) != 0) {
        return -1;
    }
    
    uint8_t token[32];
    for (int i = 0; i < 32; i++) {
        token[i] = shared_secret[i] ^ conn->local_nonce[i];
    }
    
    uint8_t token_hash[32];
    keccak256(token, 32, token_hash);
    
    uint8_t signature[64];
    if (ec_sign(conn->ephemeral_privkey, token_hash, signature) != 0) {
        return -1;
    }
    
    // 4. Build auth body: [signature, pubkey, nonce, version]
    const uint8_t* items[4] = {
        signature, 
        conn->static_pubkey + 1, // Skip 0x04 prefix
        conn->local_nonce,
        (uint8_t*)"\x04" // version
    };
    size_t lens[4] = {64, 64, 32, 1};
    
    uint8_t auth_body[256];
    size_t body_len = rlp_encode_list(items, lens, 4, auth_body);
    if (body_len == 0) return -1;
    
    // 5. Encrypt with ECIES
    return ecies_encrypt(conn->peer_static_pubkey, auth_body, body_len, auth_msg, auth_len);
}

int rlpx_process_authack(rlpx_conn_t* conn, const uint8_t* authack_msg, size_t authack_len) {
    uint8_t ack_plain[256];
    size_t plain_len = sizeof(ack_plain);
    
    // Decrypt AuthAck message
    if (ecies_decrypt(conn->static_privkey, authack_msg, authack_len, ack_plain, &plain_len) != 0) {
        return -1;
    }
    
    // Parse RLP list: [ephemeral-pubkey, nonce, version]
    uint8_t** items;
    size_t* lens;
    size_t count;
    if (rlp_decode_list(ack_plain, plain_len, &items, &lens, &count) != 0) {
        return -1;
    }
    
    if (count < 2) {
        free(items);
        free(lens);
        return -1;
    }
    
    // Extract peer ephemeral public key and nonce
    if (lens[0] == 64) {
        conn->peer_ephemeral_pubkey[0] = 0x04; // Add uncompressed prefix
        memcpy(conn->peer_ephemeral_pubkey + 1, items[0], 64);
    }
    
    if (lens[1] == 32) {
        memcpy(conn->remote_nonce, items[1], 32);
    }
    
    free(items);
    free(lens);
    return 0;
}

void rlpx_derive_secrets(rlpx_conn_t* conn) {
    // Compute shared secret
    uint8_t shared_secret[32];
    ec_ecdh(conn->ephemeral_privkey, conn->peer_ephemeral_pubkey, shared_secret);
    
    // Derive secrets using exact spec concatenations
    uint8_t keccak_input[128]; // Max size for concatenations
    
    // aes-secret = keccak(ecdhe-shared-secret || shared-secret)
    memcpy(keccak_input, shared_secret, 32);
    memcpy(keccak_input + 32, shared_secret, 32); // simplified - see spec
    keccak256(keccak_input, 64, conn->secrets.aes_secret);
    
    // mac-secret = keccak(ecdhe-shared-secret || aes-secret)  
    memcpy(keccak_input + 32, conn->secrets.aes_secret, 32);
    keccak256(keccak_input, 64, conn->secrets.mac_secret);
    
    // Initialize ingress/egress MAC states (implement per spec)
    // ingress-mac = keccak(mac-secret || recipient-nonce || initiator-auth)
    // egress-mac = keccak(mac-secret || initiator-nonce || recipient-auth)
    
    // For now, simplified:
    memcpy(conn->secrets.ingress_mac, conn->secrets.mac_secret, 32);
    memcpy(conn->secrets.egress_mac, conn->secrets.mac_secret, 32);
    
    conn->frame_enc_seed = 0;
    conn->frame_dec_seed = 0;
}

int rlpx_connect(rlpx_conn_t* conn, const char* host, uint16_t port, const char* peer_pubkey_file) {
    (void)peer_pubkey_file; // Suppress unused parameter warning
    
    // Load peer public key (implement file loading)
    // For now, placeholder
    memset(conn->peer_static_pubkey, 0x04, 65); // PLACEHOLDER
    
    // Connect TCP
    conn->sockfd = net_connect(host, port);
    if (conn->sockfd < 0) return -1;
    conn->state = RLPX_STATE_CONNECTED;
    
    // Send Auth message
    uint8_t auth_msg[512];
    size_t auth_len = sizeof(auth_msg);
    if (rlpx_create_auth(conn, auth_msg, &auth_len) != 0) {
        net_close(conn->sockfd);
        return -1;
    }
    
    if (net_send_all(conn->sockfd, auth_msg, auth_len) != (ssize_t)auth_len) {
        net_close(conn->sockfd);
        return -1;
    }
    conn->state = RLPX_STATE_SENT_AUTH;
    
    // Receive AuthAck
    uint8_t authack_msg[512];
    ssize_t recv_len = net_recv_exact(conn->sockfd, authack_msg, sizeof(authack_msg), 5000);
    if (recv_len <= 0) {
        net_close(conn->sockfd);
        return -1;
    }
    
    if (rlpx_process_authack(conn, authack_msg, recv_len) != 0) {
        net_close(conn->sockfd);
        return -1;
    }
    
    // Derive session keys
    rlpx_derive_secrets(conn);
    conn->state = RLPX_STATE_ESTABLISHED;
    
    return 0;
}

void rlpx_close(rlpx_conn_t* conn) {
    if (conn->sockfd >= 0) {
        net_close(conn->sockfd);
        conn->sockfd = -1;
    }
    conn->state = RLPX_STATE_INIT;
}

// Placeholder ECIES functions - implement according to Ethereum's ECIES variant
int ecies_encrypt(const uint8_t pubkey[65], const uint8_t* plaintext, size_t plaintext_len, 
                  uint8_t* ciphertext, size_t* ciphertext_len) {
    (void)pubkey; (void)plaintext; (void)plaintext_len; (void)ciphertext; (void)ciphertext_len;
    // TODO: Implement ECIES encryption as per Ethereum spec
    // This is a complex function involving ephemeral keys, AES, and HMAC
    return -1; // placeholder
}

int ecies_decrypt(const uint8_t privkey[32], const uint8_t* ciphertext, size_t ciphertext_len,
                  uint8_t* plaintext, size_t* plaintext_len) {
    (void)privkey; (void)ciphertext; (void)ciphertext_len; (void)plaintext; (void)plaintext_len;
    // TODO: Implement ECIES decryption as per Ethereum spec  
    return -1; // placeholder
}
