#ifndef RLP_H
#define RLP_H

#include <stdint.h>
#include <stddef.h>

// RLP encoding
size_t rlp_encode_bytes(const uint8_t* data, size_t len, uint8_t* output);
size_t rlp_encode_list(const uint8_t** items, const size_t* lens, size_t count, uint8_t* output);

// RLP decoding  
int rlp_decode_item(const uint8_t* input, size_t len, uint8_t** data, size_t* data_len);
int rlp_decode_list(const uint8_t* input, size_t len, uint8_t*** items, size_t** lens, size_t* count);

// Helper for single byte values
size_t rlp_encode_uint8(uint8_t value, uint8_t* output);

// ADDED: AuthAck-specific decode for RLPx
int rlp_decode_authack(const uint8_t* input, size_t len, 
                       uint8_t ephemeral_pubkey[65], uint8_t nonce[32]);

#endif // RLP_H
