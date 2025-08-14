#include "../src/rlpx_handshake.h"
#include "../src/rlp.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// AFL/libFuzzer compatible fuzzing entry points

// Fuzz RLP parsing
int fuzz_rlp_parsing(const uint8_t* data, size_t len) {
    if (len == 0) return 0;
    
    uint8_t* decoded_data;
    size_t decoded_len;
    
    // Test RLP item decoding - should not crash
    int result = rlp_decode_item(data, len, &decoded_data, &decoded_len);
    if (result == 0 && decoded_data) {
        free(decoded_data);
    }
    
    // Test RLP list decoding
    uint8_t** items;
    size_t* lens;
    size_t count;
    result = rlp_decode_list(data, len, &items, &lens, &count);
    if (result == 0) {
        if (items) free(items);
        if (lens) free(lens);
    }
    
    return 0;
}

// Fuzz auth message processing
int fuzz_auth_message(const uint8_t* data, size_t len) {
    if (len < 64) return 0; // Minimum size for meaningful auth
    
    rlpx_conn_t conn;
    rlpx_init(&conn, NULL);
    
    // Try to process as auth message (will likely fail, but shouldn't crash)
    rlpx_process_authack(&conn, data, len);
    
    return 0;
}

// Fuzz frame parsing
int fuzz_frame_parsing(const uint8_t* data, size_t len) {
    if (len < 19) return 0; // Minimum frame size (3 header + 16 MAC)
    
    rlpx_conn_t conn;
    rlpx_init(&conn, NULL);
    conn.state = RLPX_STATE_ESTABLISHED;
    
    // Set up dummy secrets for frame decryption
    memset(&conn.secrets, 0x42, sizeof(conn.secrets));
    
    uint8_t payload[1024];
    size_t payload_len = sizeof(payload);
    
    // Create a fake socket using the fuzz data
    // This is a simplified test - in real fuzzing you'd mock the network layer
    
    return 0;
}

// Main fuzzing entry point for AFL
#ifdef AFL_FUZZING
int main() {
    uint8_t buffer[65536];
    size_t len = read(0, buffer, sizeof(buffer));
    
    if (len > 0) {
        // Determine fuzz target based on first byte
        switch (buffer[0] % 3) {
            case 0:
                fuzz_rlp_parsing(buffer + 1, len - 1);
                break;
            case 1:
                fuzz_auth_message(buffer + 1, len - 1);
                break;
            case 2:
                fuzz_frame_parsing(buffer + 1, len - 1);
                break;
        }
    }
    
    return 0;
}
#endif

// libFuzzer entry point
#ifdef LIBFUZZER
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    
    switch (data[0] % 3) {
        case 0:
            fuzz_rlp_parsing(data + 1, size - 1);
            break;
        case 1:
            fuzz_auth_message(data + 1, size - 1);
            break;
        case 2:
            fuzz_frame_parsing(data + 1, size - 1);
            break;
    }
    
    return 0;
}
#endif
