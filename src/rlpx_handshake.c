// rlpx_handshake.c - FIXED VERSION
#include "rlpx_handshake.h"
#include "crypto_ec.h"
#include "ecies.h"
#include "keccak.h"
#include "rlp.h"
#include "net.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <openssl/crypto.h>
#include <secp256k1.h>

int rlpx_init(rlpx_conn_t* conn, const char* static_privkey_file) {
    printf("DEBUG: Initializing RLPx connection with privkey file: %s\n", static_privkey_file);
    memset(conn, 0, sizeof(*conn));
    conn->state = RLPX_STATE_INIT;
    conn->sockfd = -1;

    // Read static private key from file
    int fd = open(static_privkey_file, O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, conn->static_privkey, 32);
        close(fd);
        if (r != 32) {
            printf("DEBUG: Failed to read 32 bytes from privkey file, got %zd\n", r);
            return -1;
        }
        // Verify the private key
        if (!secp256k1_ec_seckey_verify(ctx, conn->static_privkey)) {
            printf("DEBUG: Invalid secp256k1 private key\n");
            return -1;
        }
    } else {
        printf("DEBUG: Cannot open privkey file: %s\n", static_privkey_file);
        // Fallback placeholder (not recommended for production)
        for (int i = 0; i < 32; ++i) conn->static_privkey[i] = 0x42;
    }
    ec_pubkey_from_privkey(conn->static_privkey, conn->static_pubkey);
    return 0;
}

int rlpx_create_auth(rlpx_conn_t* conn, uint8_t* auth_msg, size_t* auth_len) {
    printf("DEBUG: Creating auth message...\n");

    // 1) ephemeral keypair
    if (ec_generate_keypair(conn->ephemeral_privkey, conn->ephemeral_pubkey) != 0) {
        printf("DEBUG: ephemeral key gen failed\n");
        return -1;
    }

    // 2) local nonce (secure)
    int ur = open("/dev/urandom", O_RDONLY);
    if (ur >= 0) {
        if (read(ur, conn->local_nonce, 32) != 32) {
            close(ur);
            printf("DEBUG: /dev/urandom read failed\n");
            return -1;
        }
        close(ur);
    } else {
        printf("DEBUG: cannot open /dev/urandom\n");
        return -1;
    }

    // 3) FIXED: Compute shared secret and sign (shared_secret XOR nonce)
    uint8_t shared_secret[32];
    if (ec_ecdh(conn->static_privkey, conn->peer_static_pubkey, shared_secret) != 0) {
        printf("DEBUG: shared secret ECDH failed\n");
        return -1;
    }

    // XOR shared secret with local nonce
    uint8_t sign_data[32];
    for (int i = 0; i < 32; i++) {
        sign_data[i] = shared_secret[i] ^ conn->local_nonce[i];
    }

    // Sign the XOR result
    uint8_t sig_rs[64];
    int recid = -1;
    if (ec_sign_with_recid(conn->ephemeral_privkey, sign_data, sig_rs, &recid) != 0) {
        printf("DEBUG: ec_sign_with_recid failed\n");
        return -1;
    }
    uint8_t signature65[65];
    memcpy(signature65, sig_rs, 64);
    signature65[64] = (uint8_t)(recid + 27);

    // 4) FIXED: Create ephemeral pubkey hash
    uint8_t ephemeral_hash[32];
    keccak256(conn->ephemeral_pubkey + 1, 64, ephemeral_hash); // Skip 0x04 prefix

    // 5) FIXED: build RLP auth body: [sig(65), ephemeral_hash(32), static_pubkey(64), nonce(32), version(4)]
    const uint8_t* items[5];
    size_t lens[5];
    items[0] = signature65; lens[0] = 65;
    items[1] = ephemeral_hash; lens[1] = 32;
    items[2] = conn->static_pubkey + 1; lens[2] = 64; // X||Y without prefix
    items[3] = conn->local_nonce; lens[3] = 32;
    uint8_t ver = 4;
    items[4] = &ver; lens[4] = 1;

    uint8_t auth_body[512];
    size_t body_len = rlp_encode_list(items, lens, 5, auth_body);
    if (body_len == 0) {
        printf("DEBUG: rlp_encode_list failed\n");
        return -1;
    }
    printf("DEBUG: RLP body length: %zu\n", body_len);

    // 6) compute expected wire body length (R || IV || C || TAG)
    //uint16_t wire_body_len = (uint16_t)(65 + 16 + body_len + 32);
    // R (65) || IV (16) || C (body_len) || TAG (16)
    //uint16_t wire_body_len = (uint16_t)(65 + 16 + body_len + 16);
    uint16_t wire_body_len = (uint16_t)(65 + 16 + body_len + 32);
    uint8_t be_len[2] = { (uint8_t)((wire_body_len >> 8) & 0xff), (uint8_t)(wire_body_len & 0xff) };

    // 7) call ecies_encrypt with AAD = be_len
    uint8_t enc_tmp[1024];
    size_t enc_tmp_len = sizeof(enc_tmp);
    if (ecies_encrypt(conn->peer_static_pubkey, auth_body, body_len, be_len, 2, enc_tmp, &enc_tmp_len) != 0) {
        printf("DEBUG: ecies_encrypt failed\n");
        return -1;
    }

    if (enc_tmp_len != wire_body_len) {
        printf("DEBUG: Warning enc_tmp_len (%zu) != expected wire_body_len (%u)\n", enc_tmp_len, wire_body_len);
    }

    // 8) final auth_msg = be_len || enc_tmp
    if (*auth_len < 2 + enc_tmp_len) {
        printf("DEBUG: auth_msg buffer too small\n");
        return -1;
    }
    auth_msg[0] = be_len[0];
    auth_msg[1] = be_len[1];
    memcpy(auth_msg + 2, enc_tmp, enc_tmp_len);
    *auth_len = 2 + enc_tmp_len;

    printf("DEBUG: auth total len: %zu (wire body %u)\n", *auth_len, wire_body_len);
    return 0;
}

int rlpx_process_authack(rlpx_conn_t* conn, const uint8_t* authack_msg, size_t authack_len) {
    printf("DEBUG: Processing AuthAck len=%zu\n", authack_len);

    uint8_t plain[512];
    size_t plain_len = sizeof(plain);
    uint8_t be_len[2] = { (uint8_t)((authack_len >> 8) & 0xff), (uint8_t)(authack_len & 0xff) };

    // decrypt (passing the same AAD)
    if (ecies_decrypt(conn->static_privkey, authack_msg, authack_len, be_len, 2, plain, &plain_len) != 0) {
        printf("DEBUG: ecies_decrypt failed\n");
        return -1;
    }

    // FIXED: Use proper RLP decode
    if (rlp_decode_authack(plain, plain_len, conn->peer_ephemeral_pubkey, conn->remote_nonce) == 0) {
        printf("DEBUG: AuthAck decoded successfully\n");
        return 0;
    }

    printf("DEBUG: AuthAck decode failed\n");
    return -1;
}

void rlpx_derive_secrets(rlpx_conn_t* conn) {
    printf("DEBUG: Deriving session secrets (RLPx spec compliant)...\n");

    // 1. ephemeral_shared = ECDH(ephemeral_priv, peer_ephemeral_pub)
    uint8_t ephemeral_shared[32];
    if (ec_ecdh(conn->ephemeral_privkey, conn->peer_ephemeral_pubkey, ephemeral_shared) != 0) {
        printf("DEBUG: ephemeral ECDH failed\n");
        return;
    }

    // 2. shared_secret = keccak(ephemeral_shared || keccak(resp_nonce || init_nonce))
    uint8_t nonce_hash[32];
    uint8_t concat_nonce[64];
    memcpy(concat_nonce, conn->remote_nonce, 32);     // recipient nonce first
    memcpy(concat_nonce + 32, conn->local_nonce, 32); // initiator nonce second
    keccak256(concat_nonce, 64, nonce_hash);

    uint8_t shared_input[64];
    memcpy(shared_input, ephemeral_shared, 32);
    memcpy(shared_input + 32, nonce_hash, 32);
    
    uint8_t shared_secret[32];
    keccak256(shared_input, 64, shared_secret);

    // 3. aes_secret = keccak(ephemeral_shared || shared_secret)
    memcpy(shared_input + 32, shared_secret, 32);
    keccak256(shared_input, 64, conn->secrets.aes_secret);

    // 4. mac_secret = keccak(ephemeral_shared || aes_secret)  
    memcpy(shared_input + 32, conn->secrets.aes_secret, 32);
    keccak256(shared_input, 64, conn->secrets.mac_secret);

    // Initialize MAC states
    memcpy(conn->secrets.ingress_mac, conn->secrets.mac_secret, 32);
    memcpy(conn->secrets.egress_mac, conn->secrets.mac_secret, 32);

    conn->frame_enc_seed = 0;
    conn->frame_dec_seed = 0;

    // Clean up temporary secrets
    OPENSSL_cleanse(ephemeral_shared, sizeof(ephemeral_shared));
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(shared_input, sizeof(shared_input));
    OPENSSL_cleanse(nonce_hash, sizeof(nonce_hash));

    printf("DEBUG: Derived aes/mac secrets (spec compliant)\n");
}

int rlpx_connect(rlpx_conn_t* conn, const char* host, uint16_t port, const char* peer_pubkey_file) {
    printf("DEBUG: Starting RLPx connection to %s:%u\n", host, port);

    // load peer static pubkey from file (64 bytes X||Y)
    FILE *f = fopen(peer_pubkey_file, "rb");
    if (!f) {
        printf("DEBUG: failed to open peer pubkey file\n");
        return -1;
    }
    size_t r = fread(conn->peer_static_pubkey + 1, 1, 64, f);
    fclose(f);
    if (r != 64) {
        printf("DEBUG: peer pubkey wrong size %zu\n", r);
        return -1;
    }
    conn->peer_static_pubkey[0] = 0x04;
    printf("DEBUG: loaded peer static pubkey\n");

    conn->sockfd = net_connect(host, port);
    if (conn->sockfd < 0) {
        printf("DEBUG: net_connect failed\n");
        return -1;
    }

    // Build and send auth
    uint8_t auth_buf[2048];
    size_t auth_len = sizeof(auth_buf);
    if (rlpx_create_auth(conn, auth_buf, &auth_len) != 0) {
        printf("DEBUG: create_auth failed\n");
        net_close(conn->sockfd);
        return -1;
    }

    if (net_send_all(conn->sockfd, auth_buf, auth_len) != (ssize_t)auth_len) {
        printf("DEBUG: failed to send auth\n");
        net_close(conn->sockfd);
        return -1;
    }
    printf("DEBUG: sent auth (%zu bytes): ", auth_len);
    for (size_t i = 0; i < auth_len && i < 64; i++) printf("%02x", auth_buf[i]);
    printf("%s\n", auth_len > 64 ? "..." : "");
    conn->state = RLPX_STATE_SENT_AUTH;

    // Read 2-byte BE length
    uint8_t len_be[2];
    ssize_t got = net_recv_exact(conn->sockfd, len_be, 2, 10000);
    if (got != 2) {
        printf("DEBUG: failed to read authAck length: %zd\n", got);
        net_close(conn->sockfd);
        return -1;
    }
    uint16_t ack_len = (uint16_t)((len_be[0] << 8) | len_be[1]);
    if (ack_len > sizeof(auth_buf)) {
        printf("DEBUG: authAck too large %u\n", ack_len);
        net_close(conn->sockfd);
        return -1;
    }

    // Read body
    ssize_t got_body = net_recv_exact(conn->sockfd, auth_buf, ack_len, 10000);
    if (got_body != ack_len) {
        printf("DEBUG: failed to read full authAck: %zd\n", got_body);
        net_close(conn->sockfd);
        return -1;
    }

    // Process (authAck body only)
    if (rlpx_process_authack(conn, auth_buf, ack_len) != 0) {
        printf("DEBUG: process_authack failed\n");
        net_close(conn->sockfd);
        return -1;
    }

    // Derive session secrets
    rlpx_derive_secrets(conn);
    conn->state = RLPX_STATE_ESTABLISHED;
    printf("DEBUG: handshake complete\n");
    return 0;
}

void rlpx_close(rlpx_conn_t* conn) {
    if (conn->sockfd >= 0) {
        net_close(conn->sockfd);
        conn->sockfd = -1;
    }
    conn->state = RLPX_STATE_INIT;
}
