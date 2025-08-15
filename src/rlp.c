// Fixed src/rlp.c - Replace the entire file with this:
#include "rlp.h"
#include <string.h>
#include <stdlib.h>

size_t rlp_encode_bytes(const uint8_t* data, size_t len, uint8_t* output) {
    if (len == 1 && data[0] < 0x80) {
        // Single byte < 0x80
        output[0] = data[0];
        return 1;
    } else if (len <= 55) {
        // Short string
        output[0] = 0x80 + len;
        memcpy(output + 1, data, len);
        return 1 + len;
    } else {
        // Long string - simplified implementation
        if (len <= 0xFF) {
            output[0] = 0xb7 + 1; // 0xb7 + length of length
            output[1] = len;
            memcpy(output + 2, data, len);
            return 2 + len;
        } else if (len <= 0xFFFF) {
            output[0] = 0xb7 + 2;
            output[1] = (len >> 8) & 0xff;
            output[2] = len & 0xff;
            memcpy(output + 3, data, len);
            return 3 + len;
        }
        return 0; // Too large for this simple implementation
    }
}

size_t rlp_encode_list(const uint8_t** items, const size_t* lens, size_t count, uint8_t* output) {
    // First encode all items into a temporary buffer to calculate total size
    uint8_t temp_buffer[1024]; // Should be enough for auth message
    size_t total_payload = 0;
    size_t temp_offset = 0;
    
    // Encode each item and accumulate in temp buffer
    for (size_t i = 0; i < count; i++) {
        size_t encoded_len = rlp_encode_bytes(items[i], lens[i], temp_buffer + temp_offset);
        if (encoded_len == 0) {
            return 0; // Encoding failed
        }
        temp_offset += encoded_len;
        total_payload += encoded_len;
    }
    
    size_t offset = 0;
    
    // Now encode the list header
    if (total_payload <= 55) {
        // Short list
        output[0] = 0xc0 + total_payload;
        offset = 1;
    } else if (total_payload <= 0xFF) {
        // Long list with 1-byte length
        output[0] = 0xf7 + 1;
        output[1] = total_payload;
        offset = 2;
    } else if (total_payload <= 0xFFFF) {
        // Long list with 2-byte length
        output[0] = 0xf7 + 2;
        output[1] = (total_payload >> 8) & 0xff;
        output[2] = total_payload & 0xff;
        offset = 3;
    } else {
        return 0; // Too large for this implementation
    }
    
    // Copy the encoded items after the header
    memcpy(output + offset, temp_buffer, total_payload);
    
    return offset + total_payload;
}

size_t rlp_encode_uint8(uint8_t value, uint8_t* output) {
    return rlp_encode_bytes(&value, 1, output);
}

// Decoding functions - implement based on RLP specification
int rlp_decode_item(const uint8_t* input, size_t len, uint8_t** data, size_t* data_len) {
    // Suppress unused parameter warnings for placeholder implementation
    (void)input; (void)len; (void)data; (void)data_len;
    
    // Implementation needed based on RLP spec
    return -1; // placeholder
}

int rlp_decode_list(const uint8_t* input, size_t len, uint8_t*** items, size_t** lens, size_t* count) {
    // Suppress unused parameter warnings for placeholder implementation
    (void)input; (void)len; (void)items; (void)lens; (void)count;
    
    // Implementation needed based on RLP spec
    return -1; // placeholder
}
