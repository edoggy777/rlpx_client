#ifndef RLPX_HANDSHAKE_H
#define RLPX_HANDSHAKE_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include "keccak.h"

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
} rlpx_secrets_t;

#define RLPX_MAX_HANDSHAKE 2048
#define RLPX_MAX_FRAME     (16 * 1024 * 1024)

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

    // Raw handshake packets (size prefix included); the MAC states are
    // seeded with these, so we have to keep them around.
    uint8_t auth_packet[RLPX_MAX_HANDSHAKE];
    size_t  auth_packet_len;
    uint8_t ack_packet[RLPX_MAX_HANDSHAKE];
    size_t  ack_packet_len;

    // Derived secrets
    rlpx_secrets_t secrets;

    // Framing state. AES-256-CTR streams are continuous for the whole
    // session (one per direction), and the MACs are running keccak states.
    EVP_CIPHER_CTX* egress_cipher;
    EVP_CIPHER_CTX* ingress_cipher;
    EVP_CIPHER_CTX* mac_cipher;     // AES-256-ECB with mac-secret
    keccak_ctx_t egress_mac;
    keccak_ctx_t ingress_mac;

    // Set after Hello exchange when both sides speak p2p >= 5
    int snappy;

    // Peer Hello info
    char    peer_client_id[256];
    uint8_t peer_p2p_version;
} rlpx_conn_t;

// Handshake
int  rlpx_init(rlpx_conn_t* conn, const char* static_privkey_file);
int  rlpx_connect(rlpx_conn_t* conn, const char* host, uint16_t port, const char* peer_pubkey_file);
void rlpx_close(rlpx_conn_t* conn);
int  rlpx_create_auth(rlpx_conn_t* conn, uint8_t* auth_msg, size_t* auth_len);
int  rlpx_process_authack(rlpx_conn_t* conn, const uint8_t* authack_msg, size_t authack_len);
int  rlpx_derive_secrets(rlpx_conn_t* conn);

// Framing (rlpx_frame.c). "frame data" = rlp(msg-id) || msg-data.
int rlpx_send_frame(rlpx_conn_t* conn, const uint8_t* frame_data, size_t len);
int rlpx_recv_frame(rlpx_conn_t* conn, uint8_t* frame_data, size_t* len, int timeout_ms);
int rlpx_send_raw(rlpx_conn_t* conn, const uint8_t* data, size_t len);

// Message level: handles msg-id encoding and snappy (when negotiated).
int rlpx_send_message(rlpx_conn_t* conn, uint8_t msg_id, const uint8_t* data, size_t len);
int rlpx_recv_message(rlpx_conn_t* conn, uint8_t* msg_id, uint8_t* data, size_t* len, int timeout_ms);

// p2p base protocol helpers (rlpx_p2p.c)
int rlpx_send_hello(rlpx_conn_t* conn, const char* client_id);
int rlpx_recv_hello(rlpx_conn_t* conn, int timeout_ms);
int rlpx_send_disconnect(rlpx_conn_t* conn, uint8_t reason);
int rlpx_send_ping(rlpx_conn_t* conn);

// Key helpers (main.c-friendly): parse 32-byte privkey / 64-byte pubkey from
// either a raw binary file or a hex string.
int rlpx_load_privkey(const char* file_or_hex, uint8_t out[32]);
int rlpx_load_pubkey(const char* file_or_hex, uint8_t out[65]);

#endif // RLPX_HANDSHAKE_H
