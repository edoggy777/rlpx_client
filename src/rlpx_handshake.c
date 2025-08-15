#include "rlpx_handshake.h"
#include "crypto_ec.h"
#include "keccak.h"
#include "rlp.h"
#include "net.h"
#include "ecies.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

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
    printf("DEBUG: Creating auth message...\n");
    
    // 1. Generate ephemeral keypair
    printf("DEBUG: Generating ephemeral keypair...\n");
    if (ec_generate_keypair(conn->ephemeral_privkey, conn->ephemeral_pubkey) != 0) {
        printf("DEBUG: Failed to generate ephemeral keypair\n");
        return -1;
    }
    
    // 2. Generate random nonce (implement proper random generation)
    printf("DEBUG: Generating nonce...\n");
    //for (int i = 0; i < 32; i++) {
    //    conn->local_nonce[i] = rand() & 0xff; // PLACEHOLDER - use secure random
    //}

    printf("DEBUG: Generating secure random nonce...\n");
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0 || read(urandom_fd, conn->local_nonce, 32) != 32) {
        printf("DEBUG: Failed to read from /dev/urandom, using fallback\n");
        for (int i = 0; i < 32; i++) {
           conn->local_nonce[i] = rand() & 0xff;
        }
    }

    if (urandom_fd >= 0) close(urandom_fd);
    
    // 3. Create signature of (shared-secret ^ nonce)
    printf("DEBUG: Computing ECDH shared secret...\n");
    uint8_t shared_secret[32];
    if (ec_ecdh(conn->static_privkey, conn->peer_static_pubkey, shared_secret) != 0) {
        printf("DEBUG: ECDH failed\n");
        return -1;
    }
    
    uint8_t token[32];
    for (int i = 0; i < 32; i++) {
        token[i] = shared_secret[i] ^ conn->local_nonce[i];
    }
    
    printf("DEBUG: Hashing token...\n");
    uint8_t token_hash[32];
    keccak256(token, 32, token_hash);
    
    printf("DEBUG: Signing token hash...\n");
    uint8_t signature[64];
    if (ec_sign(conn->ephemeral_privkey, token_hash, signature) != 0) {
        printf("DEBUG: Signing failed\n");
        return -1;
    }
    
    // 4. Build auth body: [signature, pubkey, nonce, version]
    printf("DEBUG: Building RLP auth body...\n");
    const uint8_t* items[4] = {
        signature, 
        conn->static_pubkey + 1, // Skip 0x04 prefix
        conn->local_nonce,
        (uint8_t*)"\x04" // version
    };
    size_t lens[4] = {64, 64, 32, 1};
    
    uint8_t auth_body[256];
    size_t body_len = rlp_encode_list(items, lens, 4, auth_body);
    if (body_len == 0) {
        printf("DEBUG: RLP encoding failed\n");
        return -1;
    }
    printf("DEBUG: RLP auth body created, length: %zu\n", body_len);
    
    // 5. Encrypt with ECIES
    //printf("DEBUG: Encrypting auth body with ECIES...\n");
    //int result = ecies_encrypt(conn->peer_static_pubkey, auth_body, body_len, auth_msg, auth_len);
    //if (result != 0) {
    //    printf("DEBUG: ECIES encryption failed (expected - placeholder implementation)\n");
    //}
    //return result;

    // In rlpx_create_auth, after ECIES encryption:
    printf("DEBUG: Encrypting auth body with ECIES...\n");
    int result = ecies_encrypt(conn->peer_static_pubkey, auth_body, body_len, auth_msg + 2, auth_len);
    if (result != 0) {
       printf("DEBUG: ECIES encryption failed\n");
       return result;
    }

    // EIP-8: Prepend the encrypted message length (big-endian, 2 bytes)
    uint16_t encrypted_len = *auth_len;
    auth_msg[0] = (encrypted_len >> 8) & 0xff;
    auth_msg[1] = encrypted_len & 0xff;
    *auth_len += 2; // Add 2 bytes for length prefix

    printf("DEBUG: EIP-8 auth message, total length: %zu (encrypted: %u)\n", *auth_len, encrypted_len);
    
    // After the EIP-8 length prefix is added:
    printf("DEBUG: EIP-8 length prefix: 0x%02x%02x (%u bytes)\n",
           auth_msg[0], auth_msg[1], (auth_msg[0] << 8) | auth_msg[1]);

    printf("DEBUG: First 16 bytes of auth message: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", auth_msg[i]);
        }
    printf("\n");
    
    return 0;
    } 

int rlpx_process_authack(rlpx_conn_t* conn, const uint8_t* authack_msg, size_t authack_len) {
    printf("DEBUG: Processing AuthAck message (length: %zu)...\n", authack_len);
    
    uint8_t ack_plain[256];
    size_t plain_len = sizeof(ack_plain);
    
    // Decrypt AuthAck message
    printf("DEBUG: Decrypting AuthAck with ECIES...\n");
    if (ecies_decrypt(conn->static_privkey, authack_msg, authack_len, ack_plain, &plain_len) != 0) {
        printf("DEBUG: ECIES decryption failed (expected - placeholder implementation)\n");
        return -1;
    }
    
    // Parse RLP list: [ephemeral-pubkey, nonce, version]
    printf("DEBUG: Parsing AuthAck RLP...\n");
    uint8_t** items;
    size_t* lens;
    size_t count;
    if (rlp_decode_list(ack_plain, plain_len, &items, &lens, &count) != 0) {
        printf("DEBUG: RLP decoding failed\n");
        return -1;
    }
    
    if (count < 2) {
        printf("DEBUG: AuthAck has insufficient items: %zu\n", count);
        free(items);
        free(lens);
        return -1;
    }
    
    // Extract peer ephemeral public key and nonce
    if (lens[0] == 64) {
        conn->peer_ephemeral_pubkey[0] = 0x04; // Add uncompressed prefix
        memcpy(conn->peer_ephemeral_pubkey + 1, items[0], 64);
        printf("DEBUG: Extracted peer ephemeral public key\n");
    }
    
    if (lens[1] == 32) {
        memcpy(conn->remote_nonce, items[1], 32);
        printf("DEBUG: Extracted remote nonce\n");
    }
    
    free(items);
    free(lens);
    return 0;
}

void rlpx_derive_secrets(rlpx_conn_t* conn) {
    printf("DEBUG: Deriving session secrets...\n");
    
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
    
    printf("DEBUG: Session secrets derived successfully\n");
}

int rlpx_connect(rlpx_conn_t* conn, const char* host, uint16_t port, const char* peer_pubkey_file) {
    printf("DEBUG: Starting RLPx connection to %s:%d\n", host, port);
    
    printf("DEBUG: Loading peer public key from %s...\n", peer_pubkey_file);
    
    // Load peer public key from file
    FILE* pubkey_file = fopen(peer_pubkey_file, "rb");
    if (!pubkey_file) {
        printf("DEBUG: Failed to open public key file: %s\n", peer_pubkey_file);
        return -1;
    }

    // Read 64 bytes (uncompressed public key without 0x04 prefix)
    conn->peer_static_pubkey[0] = 0x04; // Add uncompressed prefix
    size_t read_bytes = fread(conn->peer_static_pubkey + 1, 1, 64, pubkey_file);
    fclose(pubkey_file);

    if (read_bytes != 64) {
        printf("DEBUG: Public key file wrong size: %zu (expected 64)\n", read_bytes);
        return -1;
    }
    printf("DEBUG: Loaded public key successfully\n");
    
    printf("DEBUG: Connecting TCP to %s:%d...\n", host, port);
    // Connect TCP
    conn->sockfd = net_connect(host, port);
    if (conn->sockfd < 0) {
        printf("DEBUG: TCP connection failed\n");
        return -1;
    }
    printf("DEBUG: TCP connection successful\n");
    conn->state = RLPX_STATE_CONNECTED;
    
    printf("DEBUG: Creating auth message...\n");
    // Send Auth message
    uint8_t auth_msg[512];
    size_t auth_len = sizeof(auth_msg);
    if (rlpx_create_auth(conn, auth_msg, &auth_len) != 0) {
        printf("DEBUG: Auth message creation failed\n");
        net_close(conn->sockfd);
        return -1;
    }
    printf("DEBUG: Auth message created, length: %zu\n", auth_len);
    
    printf("DEBUG: Sending auth message...\n");
    if (net_send_all(conn->sockfd, auth_msg, auth_len) != (ssize_t)auth_len) {
        printf("DEBUG: Failed to send auth message\n");
        net_close(conn->sockfd);
        return -1;
    }
    printf("DEBUG: Auth message sent successfully\n");
    conn->state = RLPX_STATE_SENT_AUTH;
    
    // Receive AuthAck
    printf("DEBUG: Waiting for AuthAck response...\n");
    uint8_t authack_msg[512];
    ssize_t recv_len = net_recv_exact(conn->sockfd, authack_msg, sizeof(authack_msg), 5000);
    if (recv_len <= 0) {
        printf("DEBUG: Failed to receive AuthAck (recv_len: %zd)\n", recv_len);
        net_close(conn->sockfd);
        return -1;
    }
    printf("DEBUG: Received AuthAck, length: %zd\n", recv_len);
    
    if (rlpx_process_authack(conn, authack_msg, recv_len) != 0) {
        printf("DEBUG: AuthAck processing failed\n");
        net_close(conn->sockfd);
        return -1;
    }
    printf("DEBUG: AuthAck processed successfully\n");
    
    // Derive session keys
    printf("DEBUG: Deriving session keys...\n");
    rlpx_derive_secrets(conn);
    conn->state = RLPX_STATE_ESTABLISHED;
    
    printf("DEBUG: RLPx handshake completed successfully!\n");
    return 0;
}

void rlpx_close(rlpx_conn_t* conn) {
    if (conn->sockfd >= 0) {
        net_close(conn->sockfd);
        conn->sockfd = -1;
    }
    conn->state = RLPX_STATE_INIT;
}

