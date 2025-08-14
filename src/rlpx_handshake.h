#ifndef RLPX_HANDSHAKE_H
#define RLPX_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>

// Connection state machine
typedef enum {
    RLPX_STATE_INIT,
    RLPX_STATE_CONNECTED,
    RLPX_STATE_SENT_AUTH,
    RLPX_STATE_RECV_ACK,
    RLPX_STATE_ESTABLISHED,
    RLPX_STATE_ERROR
} rlpx_state_t;

// Session keys after successful handshake
typedef struct {
    uint8_t aes_secret[32];
    uint8_t mac_secret[32];
    uint8_t ingress_aes[32];
    uint8_t egress_aes[32];
    uint8_t ingress_mac[32];
    uint8_t egress_mac[32];
} rlpx_secrets_t;

// Connection context
typedef struct {
    int sockfd;
    rlpx_state_t state;
    
    // Local keys
    uint8_t static_privkey[32];
    uint8_t static_pubkey[65];
    uint8_t ephemeral_privkey[32];
    uint8_t ephemeral_pubkey[65];
    
    // Peer keys
    uint8_t peer_static_pubkey[65];
    uint8_t peer_ephemeral_pubkey[65];
    
    // Nonces
    uint8_t local_nonce[32];
    uint8_t remote_nonce[32];
    
    // Derived secrets
    rlpx_secrets_t secrets;
    
    // Frame counters
    uint32_t frame_enc_seed;
    uint32_t frame_dec_seed;
} rlpx_conn_t;

// Core RLPx functions
int rlpx_init(rlpx_conn_t* conn, const char* static_privkey_file);
int rlpx_connect(rlpx_conn_t* conn, const char* host, uint16_t port, const char* peer_pubkey_file);
void rlpx_close(rlpx_conn_t* conn);
int rlpx_create_auth(rlpx_conn_t* conn, uint8_t* auth_msg, size_t* auth_len);
int rlpx_process_authack(rlpx_conn_t* conn, const uint8_t* authack_msg, size_t authack_len);
void rlpx_derive_secrets(rlpx_conn_t* conn);

// Frame handling functions
int rlpx_send_frame(rlpx_conn_t* conn, const uint8_t* payload, size_t len);
int rlpx_recv_frame(rlpx_conn_t* conn, uint8_t* payload, size_t* len);
int rlpx_send_raw(rlpx_conn_t* conn, const uint8_t* data, size_t len);

#endif // RLPX_HANDSHAKE_H
