// Fixed src/rlp.c - Complete implementation
#include "rlp.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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

// FIXED: Complete RLP decode implementation
int rlp_decode_item(const uint8_t* input, size_t len, uint8_t** data, size_t* data_len) {
    if (len == 0) return -1;
    
    uint8_t first = input[0];
    
    if (first < 0x80) {
        // Single byte
        *data = malloc(1);
        if (!*data) return -1;
        (*data)[0] = first;
        *data_len = 1;
        return 1; // consumed 1 byte
    } else if (first <= 0xb7) {
        // Short string
        size_t str_len = first - 0x80;
        if (len < 1 + str_len) return -1;
        
        *data = malloc(str_len);
        if (!*data) return -1;
        memcpy(*data, input + 1, str_len);
        *data_len = str_len;
        return 1 + str_len;
    } else if (first <= 0xbf) {
        // Long string
        size_t len_of_len = first - 0xb7;
        if (len < 1 + len_of_len) return -1;
        
        size_t str_len = 0;
        for (size_t i = 0; i < len_of_len; i++) {
            str_len = (str_len << 8) | input[1 + i];
        }
        
        if (len < 1 + len_of_len + str_len) return -1;
        
        *data = malloc(str_len);
        if (!*data) return -1;
        memcpy(*data, input + 1 + len_of_len, str_len);
        *data_len = str_len;
        return 1 + len_of_len + str_len;
    }
    
    return -1; // List items not handled in this function
}

int rlp_decode_list(const uint8_t* input, size_t len, uint8_t*** items, size_t** lens, size_t* count) {
    if (len == 0) return -1;
    
    uint8_t first = input[0];
    size_t payload_start = 0;
    size_t payload_len = 0;
    
    // Parse list header
    if (first >= 0xc0 && first <= 0xf7) {
        // Short list
        payload_len = first - 0xc0;
        payload_start = 1;
    } else if (first >= 0xf8 && first <= 0xff) {
        // Long list
        size_t len_of_len = first - 0xf7;
        if (len < 1 + len_of_len) return -1;
        
        payload_len = 0;
        for (size_t i = 0; i < len_of_len; i++) {
            payload_len = (payload_len << 8) | input[1 + i];
        }
        payload_start = 1 + len_of_len;
    } else {
        return -1; // Not a list
    }
    
    if (payload_start + payload_len > len) return -1;
    
    // Parse individual items
    const uint8_t* payload = input + payload_start;
    size_t offset = 0;
    size_t item_count = 0;
    
    // First pass: count items
    while (offset < payload_len) {
        uint8_t* item_data;
        size_t item_len;
        int consumed = rlp_decode_item(payload + offset, payload_len - offset, &item_data, &item_len);
        if (consumed < 0) return -1;
        
        free(item_data); // We're just counting
        offset += consumed;
        item_count++;
    }
    
    // Allocate arrays
    *items = malloc(item_count * sizeof(uint8_t*));
    *lens = malloc(item_count * sizeof(size_t));
    if (!*items || !*lens) {
        free(*items);
        free(*lens);
        return -1;
    }
    
    // Second pass: actually decode items
    offset = 0;
    *count = 0;
    while (offset < payload_len && *count < item_count) {
        int consumed = rlp_decode_item(payload + offset, payload_len - offset, 
                                      &(*items)[*count], &(*lens)[*count]);
        if (consumed < 0) {
            // Clean up on failure
            for (size_t i = 0; i < *count; i++) {
                free((*items)[i]);
            }
            free(*items);
            free(*lens);
            return -1;
        }
        
        offset += consumed;
        (*count)++;
    }
    
    return 0;
}

// FIXED: AuthAck-specific decode for RLPx
int rlp_decode_authack(const uint8_t* input, size_t len, 
                       uint8_t ephemeral_pubkey[65], uint8_t nonce[32]) {
    printf("DEBUG: Decoding AuthAck RLP, len=%zu\n", len);
    
    uint8_t** items;
    size_t* lens;
    size_t count;
    
    if (rlp_decode_list(input, len, &items, &lens, &count) != 0) {
        printf("DEBUG: RLP decode list failed\n");
        return -1;
    }
    
    if (count < 2) {
        printf("DEBUG: AuthAck has too few items: %zu\n", count);
        goto cleanup_fail;
    }
    
    // First item: ephemeral pubkey (should be 64 bytes)
    if (lens[0] == 64) {
        ephemeral_pubkey[0] = 0x04;
        memcpy(ephemeral_pubkey + 1, items[0], 64);
    } else if (lens[0] == 65 && items[0][0] == 0x04) {
        memcpy(ephemeral_pubkey, items[0], 65);
    } else {
        printf("DEBUG: Invalid ephemeral pubkey length: %zu\n", lens[0]);
        goto cleanup_fail;
    }
    
    // Second item: nonce (should be 32 bytes)
    if (lens[1] == 32) {
        memcpy(nonce, items[1], 32);
    } else {
        printf("DEBUG: Invalid nonce length: %zu\n", lens[1]);
        goto cleanup_fail;
    }
    
    // Clean up
    for (size_t i = 0; i < count; i++) {
        free(items[i]);
    }
    free(items);
    free(lens);
    
    printf("DEBUG: AuthAck decoded successfully\n");
    return 0;

cleanup_fail:
    for (size_t i = 0; i < count; i++) {
        free(items[i]);
    }
    free(items);
    free(lens);
    return -1;
}
