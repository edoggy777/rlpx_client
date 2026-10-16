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

// Wrap an already-RLP-encoded payload in a list header (for nested lists)
size_t rlp_encode_list_raw(const uint8_t* payload, size_t payload_len, uint8_t* output);
// Minimal big-endian unsigned integer (0 encodes as 0x80)
size_t rlp_encode_uint(uint64_t value, uint8_t* output);

// Generic item parser: describes the first item in input. Returns bytes
// consumed, 0 on error. For strings, *payload points at the string bytes;
// for lists, at the list payload (the encoded elements).
size_t rlp_parse(const uint8_t* input, size_t len, int* is_list,
                 const uint8_t** payload, size_t* payload_len);
uint64_t rlp_bytes_to_uint(const uint8_t* b, size_t len);

// ADDED: AuthAck-specific decode for RLPx
int rlp_decode_authack(const uint8_t* input, size_t len, 
                       uint8_t ephemeral_pubkey[65], uint8_t nonce[32]);

#endif // RLP_H
