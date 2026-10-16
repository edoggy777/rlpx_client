#include "rlpx_handshake.h"
#include "rlp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CLIENT_ID "rlpx_client/0.2/c"

void print_usage(const char* prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -h HOST        Target host (default: 127.0.0.1)\n");
    printf("  -p PORT        Target port (default: 30303)\n");
    printf("  -k KEY         Our static private key: 32-byte file, hex file, or hex string\n");
    printf("                 (optional: a random key is generated if omitted)\n");
    printf("  -P PUBKEY      Peer public key: 64-byte file, 128 hex chars, or enode:// URL\n");
    printf("  -e ENODE       Peer enode://pubkey@host:port (sets -P, -h and -p)\n");
    printf("  -m MESSAGE     Send a custom p2p message (hex payload) after Hello\n");
    printf("  -i ID          Message id for -m (default 0x10 = first eth message)\n");
    printf("  -f             Fuzz mode: send malformed frames after Hello\n");
    printf("  -n COUNT       Number of messages to read after Hello (default 2)\n");
    printf("  --help         Show this help\n");
}

void hex_dump(const uint8_t* data, size_t len, const char* prefix) {
    printf("%s", prefix);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n%*s", (int)strlen(prefix), "");
        else if ((i + 1) % 8 == 0) printf("  ");
        else printf(" ");
    }
    printf("\n");
}

static int parse_hex(const char* hex, uint8_t* out, size_t cap) {
    if (strncmp(hex, "0x", 2) == 0) hex += 2;
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return (int)(n / 2);
}

// Read and describe a few messages from the peer (Ping is answered with Pong).
static void read_messages(rlpx_conn_t* conn, int count) {
    static uint8_t buf[1 << 20];
    for (int i = 0; i < count; i++) {
        size_t len = sizeof(buf);
        uint8_t id;
        if (rlpx_recv_message(conn, &id, buf, &len, 5000) != 0) {
            printf("No further message (timeout or peer closed)\n");
            return;
        }
        const char* what = id == 0x01 ? "Disconnect" : id == 0x02 ? "Ping" : id == 0x03 ? "Pong"
                         : id == 0x10 ? "eth Status" : "message";
        printf("<- %s (id 0x%02x, %zu bytes)\n", what, id, len);
        hex_dump(buf, len > 64 ? 64 : len, "   ");
        if (len > 64) printf("   ...\n");
        if (id == 0x02) {
            uint8_t empty = 0xc0;
            rlpx_send_message(conn, 0x03, &empty, 1);
            printf("-> Pong\n");
        }
        if (id == 0x01) return;
    }
}

static int do_handshake(rlpx_conn_t* conn, const char* host, uint16_t port,
                        const char* key, const char* peer_key) {
    printf("Initializing RLPx client...\n");
    if (rlpx_init(conn, key) != 0) {
        fprintf(stderr, "Failed to initialize RLPx client\n");
        return -1;
    }
    printf("Our node id: ");
    for (int i = 1; i < 65; i++) printf("%02x", conn->static_pubkey[i]);
    printf("\n");

    printf("Connecting to %s:%u...\n", host, port);
    if (rlpx_connect(conn, host, port, peer_key) != 0) {
        fprintf(stderr, "RLPx handshake failed\n");
        return -1;
    }
    printf("✓ RLPx handshake successful (auth %zu bytes, ack %zu bytes)\n",
           conn->auth_packet_len, conn->ack_packet_len);
    hex_dump(conn->secrets.aes_secret, 32, "  AES secret: ");
    hex_dump(conn->secrets.mac_secret, 32, "  MAC secret: ");

    if (rlpx_send_hello(conn, CLIENT_ID) != 0) {
        fprintf(stderr, "Failed to send Hello\n");
        return -1;
    }
    printf("-> Hello\n");
    if (rlpx_recv_hello(conn, 10000) != 0) {
        fprintf(stderr, "Did not get a valid Hello back\n");
        return -1;
    }
    printf("✓ Hello exchange complete%s\n", conn->snappy ? " (snappy enabled)" : "");
    return 0;
}

int test_basic_connection(const char* host, uint16_t port, const char* key, const char* peer_key, int count) {
    rlpx_conn_t conn;
    if (do_handshake(&conn, host, port, key, peer_key) != 0) { rlpx_close(&conn); return 1; }
    read_messages(&conn, count);
    rlpx_send_disconnect(&conn, 0x08);   // client quitting
    rlpx_close(&conn);
    return 0;
}

int test_custom_message(const char* host, uint16_t port, const char* key, const char* peer_key,
                        uint8_t msg_id, const char* hex, int count) {
    rlpx_conn_t conn;
    uint8_t payload[4096];
    int n = parse_hex(hex, payload, sizeof(payload));
    if (n < 0) {
        fprintf(stderr, "-m expects a hex payload\n");
        return 1;
    }
    if (do_handshake(&conn, host, port, key, peer_key) != 0) { rlpx_close(&conn); return 1; }

    if (rlpx_send_message(&conn, msg_id, payload, (size_t)n) != 0) {
        fprintf(stderr, "Failed to send custom message\n");
        rlpx_close(&conn);
        return 1;
    }
    printf("-> custom message id 0x%02x (%d bytes)\n", msg_id, n);
    read_messages(&conn, count);
    rlpx_close(&conn);
    return 0;
}

int test_malformed_messages(const char* host, uint16_t port, const char* key, const char* peer_key) {
    rlpx_conn_t conn;
    if (do_handshake(&conn, host, port, key, peer_key) != 0) { rlpx_close(&conn); return 1; }
    printf("Starting malformed message tests...\n");

    // Test 1: a well-formed frame carrying an invalid RLP body for Status
    printf("Test 1: eth Status with garbage RLP\n");
    uint8_t garbage[] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA};
    rlpx_send_message(&conn, 0x10, garbage, sizeof(garbage));
    read_messages(&conn, 1);

    // Test 2: raw bytes that are not a valid frame (breaks MAC -> peer must drop us)
    printf("Test 2: raw junk on the wire (invalid header MAC)\n");
    uint8_t junk[48];
    memset(junk, 0x42, sizeof(junk));
    rlpx_send_raw(&conn, junk, sizeof(junk));
    read_messages(&conn, 1);

    printf("✓ Malformed message tests completed (peer should have dropped the connection)\n");
    rlpx_close(&conn);
    return 0;
}

static int parse_enode(const char* enode, char* host, size_t host_cap, uint16_t* port) {
    const char* at = strchr(enode, '@');
    if (!at) return -1;
    const char* colon = strrchr(at, ':');
    size_t hl = colon ? (size_t)(colon - at - 1) : strlen(at + 1);
    if (hl >= host_cap) return -1;
    memcpy(host, at + 1, hl);
    host[hl] = 0;
    if (colon) {
        *port = (uint16_t)atoi(colon + 1);
        char* q = strchr(host, '?');
        if (q) *q = 0;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    static char host_buf[256] = "127.0.0.1";
    const char* host = host_buf;
    uint16_t port = 30303;
    const char* key_file = NULL;
    const char* peer_key_file = NULL;
    const char* custom_message = NULL;
    int msg_id = 0x10;
    int fuzz_mode = 0;
    int count = 2;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            snprintf(host_buf, sizeof(host_buf), "%s", argv[++i]);
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) {
            peer_key_file = argv[++i];
        } else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
            peer_key_file = argv[++i];
            if (parse_enode(peer_key_file, host_buf, sizeof(host_buf), &port) != 0) {
                fprintf(stderr, "Bad enode URL\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            custom_message = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            msg_id = (int)strtol(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-f") == 0) {
            fuzz_mode = 1;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!peer_key_file) {
        fprintf(stderr, "Error: Peer public key (-P or -e) is required\n");
        print_usage(argv[0]);
        return 1;
    }

    printf("RLPx Test Client\n");
    printf("================\n");
    printf("Target: %s:%u\n\n", host, port);

    if (fuzz_mode)
        return test_malformed_messages(host, port, key_file, peer_key_file);
    if (custom_message)
        return test_custom_message(host, port, key_file, peer_key_file, (uint8_t)msg_id, custom_message, count);
    return test_basic_connection(host, port, key_file, peer_key_file, count);
}
