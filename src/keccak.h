#ifndef KECCAK_H
#define KECCAK_H

#include <stdint.h>
#include <stddef.h>

// Incremental Keccak-256 state. RLPx keeps two of these (egress/ingress MAC)
// alive for the whole session and repeatedly takes non-destructive digests.
typedef struct {
    uint64_t state[25];
    uint8_t  buf[136];
    size_t   buf_len;
} keccak_ctx_t;

void keccak_init(keccak_ctx_t* ctx);
void keccak_update(keccak_ctx_t* ctx, const uint8_t* data, size_t len);
// Writes the digest of everything absorbed so far WITHOUT modifying ctx
// (works on a copy), so the state can keep being updated afterwards.
void keccak_digest(const keccak_ctx_t* ctx, uint8_t out[32]);

// One-shot helper
void keccak256(const uint8_t* input, size_t len, uint8_t output[32]);

#endif // KECCAK_H
