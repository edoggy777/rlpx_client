// rlpx_handshake.c - EIP-8 RLPx handshake (initiator side)
//
// auth-body = rlp[sig, initiator-pubk, initiator-nonce, auth-vsn] || padding
// auth      = auth-size || ecies(auth-body, aad = auth-size)
// ack-body  = rlp[recipient-ephemeral-pubk, recipient-nonce, ack-vsn] || padding
#include "rlpx_handshake.h"
#include "crypto_ec.h"
#include "ecies.h"
#include "keccak.h"
#include "rlp.h"
#include "net.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <secp256k1.h>

// ---------------------------------------------------------------- key loading

static int hex_decode(const char* hex, uint8_t* out, size_t out_len) {
    if (strncmp(hex, "0x", 2) == 0) hex += 2;
    if (strlen(hex) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned v;
        if (!isxdigit((unsigned char)hex[2 * i]) || !isxdigit((unsigned char)hex[2 * i + 1])) return -1;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

// Accepts: raw binary file of exactly `len` bytes, a file containing hex, or a
// hex string given directly on the command line.
static int load_bytes(const char* file_or_hex, uint8_t* out, size_t len) {
    FILE* f = fopen(file_or_hex, "rb");
    if (!f) return hex_decode(file_or_hex, out, len);

    uint8_t buf[512];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == len) {
        memcpy(out, buf, len);
        return 0;
    }
    buf[n] = 0;
    while (n > 0 && isspace(buf[n - 1])) buf[--n] = 0;
    return hex_decode((const char*)buf, out, len);
}

int rlpx_load_privkey(const char* file_or_hex, uint8_t out[32]) {
    if (load_bytes(file_or_hex, out, 32) != 0) return -1;
    return secp256k1_ec_seckey_verify(ctx, out) ? 0 : -1;
}

int rlpx_load_pubkey(const char* file_or_hex, uint8_t out[65]) {
    // enode://<128 hex>@host:port is also accepted
    const char* s = file_or_hex;
    char tmp[129];
    if (strncmp(s, "enode://", 8) == 0) {
        s += 8;
        const char* at = strchr(s, '@');
        size_t n = at ? (size_t)(at - s) : strlen(s);
        if (n != 128) return -1;
        memcpy(tmp, s, 128);
        tmp[128] = 0;
        s = tmp;
    }
    if (load_bytes(s, out + 1, 64) != 0) return -1;
    out[0] = 0x04;
    secp256k1_pubkey pub;
    return secp256k1_ec_pubkey_parse(ctx, &pub, out, 65) ? 0 : -1;
}

// ---------------------------------------------------------------- init

int rlpx_init(rlpx_conn_t* conn, const char* static_privkey_file) {
    memset(conn, 0, sizeof(*conn));
    conn->state = RLPX_STATE_INIT;
    conn->sockfd = -1;

    // make sure libsecp256k1 context exists before we use it
    uint8_t dummy_pub[65];
    uint8_t dummy_priv[32] = {0};
    dummy_priv[31] = 1;
    ec_pubkey_from_privkey(dummy_priv, dummy_pub);

    if (static_privkey_file && rlpx_load_privkey(static_privkey_file, conn->static_privkey) == 0) {
        // loaded
    } else {
        if (static_privkey_file)
            fprintf(stderr, "Could not load private key from '%s'; generating a random one\n",
                    static_privkey_file);
        if (ec_generate_keypair(conn->static_privkey, conn->static_pubkey) != 0) return -1;
    }
    if (ec_pubkey_from_privkey(conn->static_privkey, conn->static_pubkey) != 0) return -1;
    return 0;
}

// ---------------------------------------------------------------- auth

int rlpx_create_auth(rlpx_conn_t* conn, uint8_t* auth_msg, size_t* auth_len) {
    // 1) ephemeral keypair + nonce
    if (ec_generate_keypair(conn->ephemeral_privkey, conn->ephemeral_pubkey) != 0) return -1;
    if (RAND_bytes(conn->local_nonce, 32) != 1) return -1;

    // 2) sig = sign(ephemeral-privkey, static-shared-secret ^ initiator-nonce)
    uint8_t shared[32], sign_data[32];
    if (ec_ecdh(conn->static_privkey, conn->peer_static_pubkey, shared) != 0) return -1;
    for (int i = 0; i < 32; i++) sign_data[i] = shared[i] ^ conn->local_nonce[i];
    OPENSSL_cleanse(shared, sizeof(shared));

    uint8_t sig65[65];
    int recid = 0;
    if (ec_sign_with_recid(conn->ephemeral_privkey, sign_data, sig65, &recid) != 0) return -1;
    sig65[64] = (uint8_t)recid;   // RLPx uses the raw recovery id (0/1), not 27+

    // 3) auth-body = rlp[sig, initiator-pubk(64), nonce, vsn=4]
    const uint8_t* items[4];
    size_t lens[4];
    uint8_t vsn = 4;
    items[0] = sig65;                   lens[0] = 65;
    items[1] = conn->static_pubkey + 1; lens[1] = 64;
    items[2] = conn->local_nonce;       lens[2] = 32;
    items[3] = &vsn;                    lens[3] = 1;

    uint8_t body[1024];
    size_t body_len = rlp_encode_list(items, lens, 4, body);
    if (body_len == 0) return -1;

    // EIP-8: append random padding so the packet size is not fixed
    uint8_t pad_len_byte;
    if (RAND_bytes(&pad_len_byte, 1) != 1) return -1;
    size_t pad = 100 + (pad_len_byte % 200);
    if (RAND_bytes(body + body_len, (int)pad) != 1) return -1;
    body_len += pad;

    // 4) auth-size (big-endian) is both the prefix and the ECIES shared-mac-data
    uint16_t size = (uint16_t)(ECIES_OVERHEAD + body_len);
    uint8_t prefix[2] = { (uint8_t)(size >> 8), (uint8_t)size };

    if (*auth_len < 2u + size) return -1;
    size_t enc_len = *auth_len - 2;
    if (ecies_encrypt(conn->peer_static_pubkey, body, body_len, prefix, 2, auth_msg + 2, &enc_len) != 0)
        return -1;
    if (enc_len != size) return -1;

    auth_msg[0] = prefix[0];
    auth_msg[1] = prefix[1];
    *auth_len = 2 + enc_len;
    return 0;
}

// ---------------------------------------------------------------- ack

int rlpx_process_authack(rlpx_conn_t* conn, const uint8_t* ack_body, size_t ack_len) {
    uint8_t plain[RLPX_MAX_HANDSHAKE];
    size_t plain_len = sizeof(plain);
    uint8_t prefix[2] = { (uint8_t)(ack_len >> 8), (uint8_t)ack_len };

    if (ecies_decrypt(conn->static_privkey, ack_body, ack_len, prefix, 2, plain, &plain_len) != 0) {
        fprintf(stderr, "auth-ack: ECIES decryption failed (wrong peer pubkey or our key?)\n");
        return -1;
    }

    // rlp[recipient-ephemeral-pubk, recipient-nonce, ack-vsn] (+ ignored padding)
    int is_list;
    const uint8_t *list, *p;
    size_t list_len, plen, used;
    if (rlp_parse(plain, plain_len, &is_list, &list, &list_len) == 0 || !is_list) {
        fprintf(stderr, "auth-ack: not an RLP list\n");
        return -1;
    }
    used = rlp_parse(list, list_len, &is_list, &p, &plen);
    if (used == 0 || is_list || plen != 64) {
        fprintf(stderr, "auth-ack: bad ephemeral pubkey\n");
        return -1;
    }
    conn->peer_ephemeral_pubkey[0] = 0x04;
    memcpy(conn->peer_ephemeral_pubkey + 1, p, 64);
    list += used; list_len -= used;

    used = rlp_parse(list, list_len, &is_list, &p, &plen);
    if (used == 0 || is_list || plen != 32) {
        fprintf(stderr, "auth-ack: bad nonce\n");
        return -1;
    }
    memcpy(conn->remote_nonce, p, 32);
    return 0;
}

// ---------------------------------------------------------------- secrets

int rlpx_derive_secrets(rlpx_conn_t* conn) {
    uint8_t ephemeral_key[32], tmp[64], shared_secret[32];

    // ephemeral-key = ecdh(ephemeral-privkey, remote-ephemeral-pubk)
    if (ec_ecdh(conn->ephemeral_privkey, conn->peer_ephemeral_pubkey, ephemeral_key) != 0) return -1;

    // shared-secret = keccak(ephemeral-key || keccak(recipient-nonce || initiator-nonce))
    memcpy(tmp, conn->remote_nonce, 32);
    memcpy(tmp + 32, conn->local_nonce, 32);
    keccak256(tmp, 64, tmp + 32);
    memcpy(tmp, ephemeral_key, 32);
    keccak256(tmp, 64, shared_secret);

    // aes-secret = keccak(ephemeral-key || shared-secret)
    memcpy(tmp + 32, shared_secret, 32);
    keccak256(tmp, 64, conn->secrets.aes_secret);

    // mac-secret = keccak(ephemeral-key || aes-secret)
    memcpy(tmp + 32, conn->secrets.aes_secret, 32);
    keccak256(tmp, 64, conn->secrets.mac_secret);

    // egress-mac  = keccak.init((mac-secret ^ recipient-nonce) || auth)
    // ingress-mac = keccak.init((mac-secret ^ initiator-nonce) || ack)
    uint8_t x[32];
    keccak_init(&conn->egress_mac);
    for (int i = 0; i < 32; i++) x[i] = conn->secrets.mac_secret[i] ^ conn->remote_nonce[i];
    keccak_update(&conn->egress_mac, x, 32);
    keccak_update(&conn->egress_mac, conn->auth_packet, conn->auth_packet_len);

    keccak_init(&conn->ingress_mac);
    for (int i = 0; i < 32; i++) x[i] = conn->secrets.mac_secret[i] ^ conn->local_nonce[i];
    keccak_update(&conn->ingress_mac, x, 32);
    keccak_update(&conn->ingress_mac, conn->ack_packet, conn->ack_packet_len);

    // AES-256-CTR streams with zero IV, one per direction, plus AES-256-ECB for MAC
    uint8_t iv[16] = {0};
    conn->egress_cipher = EVP_CIPHER_CTX_new();
    conn->ingress_cipher = EVP_CIPHER_CTX_new();
    conn->mac_cipher = EVP_CIPHER_CTX_new();
    if (!conn->egress_cipher || !conn->ingress_cipher || !conn->mac_cipher) return -1;
    if (EVP_EncryptInit_ex(conn->egress_cipher, EVP_aes_256_ctr(), NULL, conn->secrets.aes_secret, iv) != 1) return -1;
    if (EVP_EncryptInit_ex(conn->ingress_cipher, EVP_aes_256_ctr(), NULL, conn->secrets.aes_secret, iv) != 1) return -1;
    if (EVP_EncryptInit_ex(conn->mac_cipher, EVP_aes_256_ecb(), NULL, conn->secrets.mac_secret, NULL) != 1) return -1;
    EVP_CIPHER_CTX_set_padding(conn->mac_cipher, 0);

    OPENSSL_cleanse(ephemeral_key, sizeof(ephemeral_key));
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
    OPENSSL_cleanse(tmp, sizeof(tmp));
    OPENSSL_cleanse(conn->ephemeral_privkey, 32);
    return 0;
}

// ---------------------------------------------------------------- connect

int rlpx_connect(rlpx_conn_t* conn, const char* host, uint16_t port, const char* peer_pubkey_file) {
    if (rlpx_load_pubkey(peer_pubkey_file, conn->peer_static_pubkey) != 0) {
        fprintf(stderr, "Could not load peer public key from '%s' (need 64-byte file, 128 hex chars, or enode://)\n",
                peer_pubkey_file);
        return -1;
    }

    conn->sockfd = net_connect(host, port);
    if (conn->sockfd < 0) return -1;
    conn->state = RLPX_STATE_CONNECTED;

    // auth
    conn->auth_packet_len = sizeof(conn->auth_packet);
    if (rlpx_create_auth(conn, conn->auth_packet, &conn->auth_packet_len) != 0) {
        fprintf(stderr, "Failed to build auth message\n");
        goto fail;
    }
    if (net_send_all(conn->sockfd, conn->auth_packet, conn->auth_packet_len) != (ssize_t)conn->auth_packet_len) {
        fprintf(stderr, "Failed to send auth\n");
        goto fail;
    }
    conn->state = RLPX_STATE_SENT_AUTH;

    // ack: 2-byte size prefix then body
    if (net_recv_exact(conn->sockfd, conn->ack_packet, 2, 10000) != 2) {
        fprintf(stderr, "Did not receive auth-ack (peer closed? wrong peer pubkey?)\n");
        goto fail;
    }
    uint16_t ack_size = (uint16_t)((conn->ack_packet[0] << 8) | conn->ack_packet[1]);
    if (ack_size < ECIES_OVERHEAD || (size_t)ack_size + 2 > sizeof(conn->ack_packet)) {
        fprintf(stderr, "auth-ack size %u out of range\n", ack_size);
        goto fail;
    }
    if (net_recv_exact(conn->sockfd, conn->ack_packet + 2, ack_size, 10000) != ack_size) {
        fprintf(stderr, "Short auth-ack\n");
        goto fail;
    }
    conn->ack_packet_len = 2u + ack_size;
    conn->state = RLPX_STATE_RECV_ACK;

    if (rlpx_process_authack(conn, conn->ack_packet + 2, ack_size) != 0) goto fail;
    if (rlpx_derive_secrets(conn) != 0) {
        fprintf(stderr, "Secret derivation failed\n");
        goto fail;
    }
    conn->state = RLPX_STATE_ESTABLISHED;
    return 0;

fail:
    net_close(conn->sockfd);
    conn->sockfd = -1;
    conn->state = RLPX_STATE_ERROR;
    return -1;
}

void rlpx_close(rlpx_conn_t* conn) {
    if (conn->sockfd >= 0) {
        net_close(conn->sockfd);
        conn->sockfd = -1;
    }
    if (conn->egress_cipher)  EVP_CIPHER_CTX_free(conn->egress_cipher);
    if (conn->ingress_cipher) EVP_CIPHER_CTX_free(conn->ingress_cipher);
    if (conn->mac_cipher)     EVP_CIPHER_CTX_free(conn->mac_cipher);
    conn->egress_cipher = conn->ingress_cipher = conn->mac_cipher = NULL;
    OPENSSL_cleanse(&conn->secrets, sizeof(conn->secrets));
    conn->state = RLPX_STATE_INIT;
}
