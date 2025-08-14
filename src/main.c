#include "rlpx_handshake.h"
#include "rlp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void print_usage(const char* prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -h HOST        Target host (default: 127.0.0.1)\n");
    printf("  -p PORT        Target port (default: 30303)\n");
    printf("  -k KEYFILE     Static private key file\n");
    printf("  -P PUBKEYFILE  Peer public key file\n");
    printf("  -m MESSAGE     Send custom message after handshake\n");
    printf("  -f             Fuzz mode: send malformed frames\n");
    printf("  --help         Show this help\n");
}

int load_key_from_file(const char* filename, uint8_t* key, size_t key_len) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open key file: %s\n", filename);
        return -1;
    }
    
    size_t read_len = fread(key, 1, key_len, f);
    fclose(f);
    
    if (read_len != key_len) {
        fprintf(stderr, "Key file has wrong size: %zu (expected %zu)\n", read_len, key_len);
        return -1;
    }
    
    return 0;
}

void hex_dump(const uint8_t* data, size_t len, const char* prefix) {
    printf("%s", prefix);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n%*s", (int)strlen(prefix), "");
        else if ((i + 1) % 8 == 0) printf("  ");
        else printf(" ");
    }
    printf("\n");
}

// Basic connection test
int test_basic_connection(const char* host, uint16_t port, const char* key_file, const char* peer_key_file) {
    rlpx_conn_t conn;
    
    printf("Initializing RLPx client...\n");
    if (rlpx_init(&conn, key_file) != 0) {
        fprintf(stderr, "Failed to initialize RLPx client\n");
        return 1;
    }
    
    printf("Connecting to %s:%d...\n", host, port);
    if (rlpx_connect(&conn, host, port, peer_key_file) != 0) {
        fprintf(stderr, "RLPx handshake failed\n");
        return 1;
    }
    
    printf("✓ RLPx handshake successful!\n");
    printf("Connection established with secrets:\n");
    hex_dump(conn.secrets.aes_secret, 32, "  AES Secret: ");
    hex_dump(conn.secrets.mac_secret, 32, "  MAC Secret: ");
    
    rlpx_close(&conn);
    return 0;
}

// Send custom message after handshake
int test_custom_message(const char* host, uint16_t port, const char* key_file, 
                       const char* peer_key_file, const char* message) {
    rlpx_conn_t conn;
    
    if (rlpx_init(&conn, key_file) != 0 || 
        rlpx_connect(&conn, host, port, peer_key_file) != 0) {
        fprintf(stderr, "Connection failed\n");
        return 1;
    }
    
    printf("✓ Connected. Sending custom message...\n");
    
    // Create a basic Hello message (protocol ID 0x00)
    uint8_t hello_payload[64];
    hello_payload[0] = 0x00; // Protocol ID for Hello
    
    // Add custom message data
    size_t msg_len = strlen(message);
    if (msg_len > 63) msg_len = 63; // Limit message size
    memcpy(hello_payload + 1, message, msg_len);
    
    if (rlpx_send_frame(&conn, hello_payload, msg_len + 1) != 0) {
        fprintf(stderr, "Failed to send custom message\n");
        rlpx_close(&conn);
        return 1;
    }
    
    printf("✓ Custom message sent: %s\n", message);
    
    // Try to receive response
    uint8_t response[1024];
    size_t response_len = sizeof(response);
    
    printf("Waiting for response...\n");
    if (rlpx_recv_frame(&conn, response, &response_len) == 0) {
        printf("✓ Received response (%zu bytes):\n", response_len);
        hex_dump(response, response_len, "  ");
    } else {
        printf("No response received (this is normal for some messages)\n");
    }
    
    rlpx_close(&conn);
    return 0;
}

// Malformed message testing for fuzzing
int test_malformed_messages(const char* host, uint16_t port, const char* key_file, const char* peer_key_file) {
    rlpx_conn_t conn;
    
    if (rlpx_init(&conn, key_file) != 0 || 
        rlpx_connect(&conn, host, port, peer_key_file) != 0) {
        fprintf(stderr, "Connection failed\n");
        return 1;
    }
    
    printf("✓ Connected. Starting malformed message tests...\n");
    
    // Test 1: Send frame with invalid length
    printf("Test 1: Invalid frame length\n");
    uint8_t malformed1[] = {0xFF, 0xFF, 0xFF, 0x42, 0x42, 0x42};
    rlpx_send_raw(&conn, malformed1, sizeof(malformed1));
    
    // Test 2: Send corrupted RLP data
    printf("Test 2: Corrupted RLP payload\n");
    uint8_t malformed_rlp[] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA};
    rlpx_send_frame(&conn, malformed_rlp, sizeof(malformed_rlp));
    
    // Test 3: Send frame with wrong MAC
    printf("Test 3: Frame with invalid MAC\n");
    uint8_t frame_header[] = {0x00, 0x00, 0x04}; // 4-byte payload
    uint8_t payload[] = {0x01, 0x02, 0x03, 0x04};
    uint8_t fake_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    rlpx_send_raw(&conn, frame_header, 3);
    rlpx_send_raw(&conn, payload, 4);
    rlpx_send_raw(&conn, fake_mac, 16);
    
    printf("✓ Malformed message tests completed\n");
    printf("Note: Peer may have disconnected due to protocol violations\n");
    
    rlpx_close(&conn);
    return 0;
}

int main(int argc, char* argv[]) {
    const char* host = "127.0.0.1";
    uint16_t port = 30303;
    const char* key_file = NULL;
    const char* peer_key_file = NULL;
    const char* custom_message = NULL;
    int fuzz_mode = 0;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc) {
            peer_key_file = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            custom_message = argv[++i];
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
    
    // Validate required arguments
    if (!key_file) {
        fprintf(stderr, "Error: Static private key file (-k) is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (!peer_key_file) {
        fprintf(stderr, "Error: Peer public key file (-P) is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    printf("RLPx Test Client\n");
    printf("================\n");
    printf("Target: %s:%d\n", host, port);
    printf("Private key: %s\n", key_file);
    printf("Peer pubkey: %s\n", peer_key_file);
    printf("\n");
    
    // Run appropriate test based on options
    if (fuzz_mode) {
        return test_malformed_messages(host, port, key_file, peer_key_file);
    } else if (custom_message) {
        return test_custom_message(host, port, key_file, peer_key_file, custom_message);
    } else {
        return test_basic_connection(host, port, key_file, peer_key_file);
    }
}
