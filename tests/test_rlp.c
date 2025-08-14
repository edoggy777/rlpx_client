#include "../src/rlp.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void test_rlp_single_byte() {
    uint8_t input = 0x42;
    uint8_t output[16];
    
    size_t encoded_len = rlp_encode_bytes(&input, 1, output);
    assert(encoded_len == 1);
    assert(output[0] == 0x42);
    
    printf("✓ RLP single byte encoding test passed\n");
}

void test_rlp_short_string() {
    uint8_t input[] = "hello";
    uint8_t expected[] = {0x85, 'h', 'e', 'l', 'l', 'o'};
    uint8_t output[16];
    
    size_t encoded_len = rlp_encode_bytes(input, 5, output);
    assert(encoded_len == 6);
    assert(memcmp(output, expected, 6) == 0);
    
    printf("✓ RLP short string encoding test passed\n");
}

int main() {
    test_rlp_single_byte();
    test_rlp_short_string();
    printf("All RLP tests passed!\n");
    return 0;
}
