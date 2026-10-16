// src/rlpx_p2p.c - devp2p base protocol messages (Hello / Disconnect / Ping / Pong)
#include "rlpx_handshake.h"
#include "rlp.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define P2P_HELLO      0x00
#define P2P_DISCONNECT 0x01
#define P2P_PING       0x02
#define P2P_PONG       0x03
#define P2P_VERSION    5

static const char* disconnect_reason(uint8_t r) {
    static const char* names[] = {
        "disconnect requested", "tcp subsystem error", "breach of protocol",
        "useless peer", "too many peers", "already connected",
        "incompatible p2p version", "null node identity", "client quitting",
        "unexpected identity", "connected to self", "read timeout", "", "", "",
        "", "subprotocol error"
    };
    return r < sizeof(names) / sizeof(names[0]) ? names[r] : "unknown";
}

// Hello: rlp[protocolVersion, clientId, [[cap, ver], ...], listenPort, nodeId]
int rlpx_send_hello(rlpx_conn_t* conn, const char* client_id) {
    uint8_t caps_payload[64], caps[72], items[512], body[600];
    size_t n = 0;

    // capabilities: advertise eth/68 so real nodes don't drop us as useless
    uint8_t cap[16];
    size_t c = rlp_encode_bytes((const uint8_t*)"eth", 3, cap);
    c += rlp_encode_uint(68, cap + c);
    size_t cp = rlp_encode_list_raw(cap, c, caps_payload);
    size_t caps_len = rlp_encode_list_raw(caps_payload, cp, caps);

    n += rlp_encode_uint(P2P_VERSION, items + n);
    n += rlp_encode_bytes((const uint8_t*)client_id, strlen(client_id), items + n);
    memcpy(items + n, caps, caps_len); n += caps_len;
    n += rlp_encode_uint(0, items + n);                       // listen port
    n += rlp_encode_bytes(conn->static_pubkey + 1, 64, items + n);

    size_t body_len = rlp_encode_list_raw(items, n, body);
    // Hello is never snappy-compressed; make sure the flag is off while sending it
    int saved = conn->snappy;
    conn->snappy = 0;
    int rc = rlpx_send_message(conn, P2P_HELLO, body, body_len);
    conn->snappy = saved;
    return rc;
}

int rlpx_recv_hello(rlpx_conn_t* conn, int timeout_ms) {
    uint8_t buf[4096];
    size_t len = sizeof(buf);
    uint8_t id;

    int saved = conn->snappy;
    conn->snappy = 0;
    int rc = rlpx_recv_message(conn, &id, buf, &len, timeout_ms);
    conn->snappy = saved;
    if (rc != 0) return -1;

    int is_list;
    const uint8_t *list, *p;
    size_t list_len, plen, used;

    if (id == P2P_DISCONNECT) {
        // rlp[reason] (older clients send a bare integer)
        uint8_t reason = 0;
        if (rlp_parse(buf, len, &is_list, &list, &list_len)) {
            if (is_list) rlp_parse(list, list_len, &is_list, &p, &plen);
            else { p = list; plen = list_len; }
            reason = (uint8_t)rlp_bytes_to_uint(p, plen);
        }
        fprintf(stderr, "Peer sent Disconnect before Hello: reason %u (%s)\n", reason, disconnect_reason(reason));
        return -1;
    }
    if (id != P2P_HELLO) {
        fprintf(stderr, "Expected Hello (0x00), got message id 0x%02x\n", id);
        return -1;
    }

    if (!rlp_parse(buf, len, &is_list, &list, &list_len) || !is_list) return -1;

    // protocolVersion
    used = rlp_parse(list, list_len, &is_list, &p, &plen);
    if (!used || is_list) return -1;
    conn->peer_p2p_version = (uint8_t)rlp_bytes_to_uint(p, plen);
    list += used; list_len -= used;

    // clientId
    used = rlp_parse(list, list_len, &is_list, &p, &plen);
    if (!used || is_list) return -1;
    size_t cl = plen < sizeof(conn->peer_client_id) - 1 ? plen : sizeof(conn->peer_client_id) - 1;
    memcpy(conn->peer_client_id, p, cl);
    conn->peer_client_id[cl] = 0;
    list += used; list_len -= used;

    // capabilities
    printf("Peer Hello: p2p v%u, client \"%s\"\n", conn->peer_p2p_version, conn->peer_client_id);
    used = rlp_parse(list, list_len, &is_list, &p, &plen);
    if (!used || !is_list) return -1;
    printf("  capabilities:");
    {
        const uint8_t* cp = p;
        size_t cl2 = plen;
        while (cl2 > 0) {
            const uint8_t *cap, *name, *ver;
            size_t cap_len, name_len, ver_len, u, u2;
            u = rlp_parse(cp, cl2, &is_list, &cap, &cap_len);
            if (!u || !is_list) break;
            u2 = rlp_parse(cap, cap_len, &is_list, &name, &name_len);
            if (!u2) break;
            if (!rlp_parse(cap + u2, cap_len - u2, &is_list, &ver, &ver_len)) break;
            printf(" %.*s/%llu", (int)name_len, name, (unsigned long long)rlp_bytes_to_uint(ver, ver_len));
            cp += u; cl2 -= u;
        }
    }
    printf("\n");
    list += used; list_len -= used;

    // listenPort
    used = rlp_parse(list, list_len, &is_list, &p, &plen);
    if (!used) return -1;
    list += used; list_len -= used;

    // nodeId
    used = rlp_parse(list, list_len, &is_list, &p, &plen);
    if (!used || plen != 64) return -1;
    if (memcmp(p, conn->peer_static_pubkey + 1, 64) != 0) {
        fprintf(stderr, "Warning: Hello node id does not match the peer pubkey we dialed\n");
    }

    // snappy is used when both sides speak p2p >= 5
    conn->snappy = conn->peer_p2p_version >= 5 && P2P_VERSION >= 5;
    return 0;
}

int rlpx_send_disconnect(rlpx_conn_t* conn, uint8_t reason) {
    uint8_t item[2], body[4];
    size_t n = rlp_encode_uint(reason, item);
    size_t body_len = rlp_encode_list_raw(item, n, body);
    return rlpx_send_message(conn, P2P_DISCONNECT, body, body_len);
}

int rlpx_send_ping(rlpx_conn_t* conn) {
    uint8_t body[1] = { 0xc0 };   // empty list
    return rlpx_send_message(conn, P2P_PING, body, 1);
}
