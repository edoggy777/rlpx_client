// src/rlpx_frame.c - RLPx framing
//
//   frame = header-ciphertext(16) || header-mac(16) || frame-ciphertext || frame-mac(16)
//   header = frame-size(3) || rlp[0, 0] || zero-pad to 16
//   frame-data = rlp(msg-id) || msg-data, zero-padded to a multiple of 16
//
//   header-mac: egress-mac.update(aes(mac-secret, egress-mac.digest[:16]) ^ header-ciphertext)
//               header-mac = egress-mac.digest[:16]
//   frame-mac:  egress-mac.update(frame-ciphertext)
//               seed = egress-mac.digest[:16]
//               egress-mac.update(aes(mac-secret, seed) ^ seed)
//               frame-mac = egress-mac.digest[:16]
#include "rlpx_handshake.h"
#include "rlp.h"
#include "snappy.h"
#include "net.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/crypto.h>

static int ctr_xor(EVP_CIPHER_CTX* c, const uint8_t* in, size_t len, uint8_t* out) {
    int outl = 0;
    if (len == 0) return 0;
    if (EVP_EncryptUpdate(c, out, &outl, in, (int)len) != 1 || (size_t)outl != len) return -1;
    return 0;
}

// mac.update(aes(mac-secret, mac.digest[:16]) ^ seed); return mac.digest[:16]
static int mac_update_seed(rlpx_conn_t* conn, keccak_ctx_t* mac, const uint8_t seed[16], uint8_t out[16]) {
    uint8_t digest[32], enc[16];
    int outl = 0;
    keccak_digest(mac, digest);
    if (EVP_EncryptUpdate(conn->mac_cipher, enc, &outl, digest, 16) != 1 || outl != 16) return -1;
    for (int i = 0; i < 16; i++) enc[i] ^= seed[i];
    keccak_update(mac, enc, 16);
    keccak_digest(mac, digest);
    memcpy(out, digest, 16);
    return 0;
}

int rlpx_send_frame(rlpx_conn_t* conn, const uint8_t* frame_data, size_t len) {
    if (conn->state != RLPX_STATE_ESTABLISHED) return -1;
    if (len > 0xFFFFFF) return -1;

    size_t padded = (len + 15) & ~(size_t)15;
    size_t total = 32 + padded + 16;
    uint8_t* out = calloc(1, total);
    if (!out) return -1;

    // header
    uint8_t header[16] = {0};
    header[0] = (uint8_t)(len >> 16);
    header[1] = (uint8_t)(len >> 8);
    header[2] = (uint8_t)len;
    header[3] = 0xc2; header[4] = 0x80; header[5] = 0x80;   // rlp[0, 0]
    if (ctr_xor(conn->egress_cipher, header, 16, out) != 0) goto fail;
    if (mac_update_seed(conn, &conn->egress_mac, out, out + 16) != 0) goto fail;

    // body
    uint8_t* body = out + 32;
    memcpy(body, frame_data, len);                 // trailing bytes already zero
    if (ctr_xor(conn->egress_cipher, body, padded, body) != 0) goto fail;
    keccak_update(&conn->egress_mac, body, padded);
    uint8_t seed[32];
    keccak_digest(&conn->egress_mac, seed);
    if (mac_update_seed(conn, &conn->egress_mac, seed, body + padded) != 0) goto fail;

    ssize_t sent = net_send_all(conn->sockfd, out, total);
    free(out);
    return sent == (ssize_t)total ? 0 : -1;
fail:
    free(out);
    return -1;
}

int rlpx_recv_frame(rlpx_conn_t* conn, uint8_t* frame_data, size_t* len, int timeout_ms) {
    if (conn->state != RLPX_STATE_ESTABLISHED) return -1;

    uint8_t hdr[32];
    if (net_recv_exact(conn->sockfd, hdr, 32, timeout_ms) != 32) return -1;

    uint8_t mac[16];
    if (mac_update_seed(conn, &conn->ingress_mac, hdr, mac) != 0) return -1;
    if (CRYPTO_memcmp(mac, hdr + 16, 16) != 0) {
        fprintf(stderr, "rlpx: bad header MAC\n");
        return -1;
    }
    uint8_t header[16];
    if (ctr_xor(conn->ingress_cipher, hdr, 16, header) != 0) return -1;

    size_t frame_len = ((size_t)header[0] << 16) | ((size_t)header[1] << 8) | header[2];
    size_t padded = (frame_len + 15) & ~(size_t)15;
    if (frame_len > RLPX_MAX_FRAME) return -1;

    uint8_t* body = malloc(padded + 16);
    if (!body) return -1;
    if (net_recv_exact(conn->sockfd, body, padded + 16, timeout_ms) != (ssize_t)(padded + 16)) {
        free(body);
        return -1;
    }

    keccak_update(&conn->ingress_mac, body, padded);
    uint8_t seed[32];
    keccak_digest(&conn->ingress_mac, seed);
    if (mac_update_seed(conn, &conn->ingress_mac, seed, mac) != 0) { free(body); return -1; }
    if (CRYPTO_memcmp(mac, body + padded, 16) != 0) {
        fprintf(stderr, "rlpx: bad frame MAC\n");
        free(body);
        return -1;
    }

    if (frame_len > *len) {
        fprintf(stderr, "rlpx: frame of %zu bytes does not fit in %zu-byte buffer\n", frame_len, *len);
        free(body);
        return -1;
    }
    // decrypt the whole padded block to keep the CTR stream in sync
    if (ctr_xor(conn->ingress_cipher, body, padded, body) != 0) { free(body); return -1; }
    memcpy(frame_data, body, frame_len);
    *len = frame_len;
    free(body);
    return 0;
}

int rlpx_send_raw(rlpx_conn_t* conn, const uint8_t* data, size_t len) {
    if (conn->sockfd < 0) return -1;
    return net_send_all(conn->sockfd, data, len) == (ssize_t)len ? 0 : -1;
}

// ---------------------------------------------------------------- messages

int rlpx_send_message(rlpx_conn_t* conn, uint8_t msg_id, const uint8_t* data, size_t len) {
    size_t cap = 1 + snappy_max_compressed(len) + len;
    uint8_t* frame = malloc(cap);
    if (!frame) return -1;
    size_t n = rlp_encode_uint(msg_id, frame);
    if (conn->snappy) {
        size_t c = snappy_compress(data, len, frame + n, cap - n);
        if (c == 0 && len > 0) { free(frame); return -1; }
        n += c;
    } else {
        memcpy(frame + n, data, len);
        n += len;
    }
    int rc = rlpx_send_frame(conn, frame, n);
    free(frame);
    return rc;
}

int rlpx_recv_message(rlpx_conn_t* conn, uint8_t* msg_id, uint8_t* data, size_t* len, int timeout_ms) {
    size_t cap = *len + 16;
    uint8_t* frame = malloc(cap);
    if (!frame) return -1;
    size_t flen = cap;
    if (rlpx_recv_frame(conn, frame, &flen, timeout_ms) != 0) { free(frame); return -1; }

    int is_list;
    const uint8_t* p;
    size_t plen;
    size_t used = rlp_parse(frame, flen, &is_list, &p, &plen);
    if (used == 0 || is_list || plen > 1) { free(frame); return -1; }
    *msg_id = plen ? p[0] : 0;

    const uint8_t* body = frame + used;
    size_t body_len = flen - used;
    // Some clients (ethereumjs, old geth) send Disconnect uncompressed even
    // after snappy was negotiated; accept raw data for that message.
    int try_raw = (*msg_id == 0x01);
    if (conn->snappy && body_len > 0) {
        size_t ulen = snappy_uncompressed_length(body, body_len);
        size_t got = 0;
        if (ulen != 0 && ulen <= *len) got = snappy_uncompress(body, body_len, data, *len);
        if (got == 0) {
            if (try_raw && body_len <= *len) {
                memcpy(data, body, body_len);
                *len = body_len;
                free(frame);
                return 0;
            }
            fprintf(stderr, "rlpx: snappy decompression failed (msg id 0x%02x, %zu bytes)\n", *msg_id, body_len);
            free(frame);
            return -1;
        }
        *len = got;
    } else {
        if (body_len > *len) { free(frame); return -1; }
        memcpy(data, body, body_len);
        *len = body_len;
    }
    free(frame);
    return 0;
}
