// src/keccak.c
// Keccak-256 (the original pre-SHA3 padding used by Ethereum) with an
// incremental API, because RLPx frame MACs are running keccak states.

#include "keccak.h"
#include <string.h>
#include <stdint.h>

#define KECCAK_ROUNDS 24
#define KECCAK_RATE   136   // 1600 - 2*256 bits = 136 bytes

static const uint64_t RC[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Rotation offsets indexed by x + 5*y
static const unsigned int RHO[25] = {
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

static inline uint64_t rotl64(uint64_t x, unsigned int n) {
    return n == 0 ? x : (x << n) | (x >> (64 - n));
}

static void keccak_f1600(uint64_t A[25]) {
    uint64_t C[5], D[5], B[25];

    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        // Theta
        for (int x = 0; x < 5; x++)
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        for (int x = 0; x < 5; x++)
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        for (int i = 0; i < 25; i++)
            A[i] ^= D[i % 5];

        // Rho + Pi:  B[y, 2x+3y] = rot(A[x, y], r[x, y])
        // (previous version had x/y swapped in the destination index)
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(A[x + 5 * y], RHO[x + 5 * y]);

        // Chi
        for (int y = 0; y < 5; y++)
            for (int x = 0; x < 5; x++)
                A[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);

        // Iota
        A[0] ^= RC[round];
    }
}

static void absorb_block(keccak_ctx_t* ctx, const uint8_t* block) {
    // little-endian lane loading, works on any host endianness
    for (size_t i = 0; i < KECCAK_RATE / 8; i++) {
        uint64_t lane = 0;
        for (int b = 7; b >= 0; b--) lane = (lane << 8) | block[i * 8 + b];
        ctx->state[i] ^= lane;
    }
    keccak_f1600(ctx->state);
}

void keccak_init(keccak_ctx_t* ctx) {
    memset(ctx, 0, sizeof(*ctx));
}

void keccak_update(keccak_ctx_t* ctx, const uint8_t* data, size_t len) {
    while (len > 0) {
        size_t space = KECCAK_RATE - ctx->buf_len;
        size_t take = len < space ? len : space;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == KECCAK_RATE) {
            absorb_block(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

void keccak_digest(const keccak_ctx_t* in, uint8_t out[32]) {
    keccak_ctx_t ctx = *in;   // copy so the caller's state is untouched

    // Keccak (non-SHA3) padding: 0x01 ... 0x80
    memset(ctx.buf + ctx.buf_len, 0, KECCAK_RATE - ctx.buf_len);
    ctx.buf[ctx.buf_len] ^= 0x01;
    ctx.buf[KECCAK_RATE - 1] ^= 0x80;
    absorb_block(&ctx, ctx.buf);

    for (int i = 0; i < 4; i++) {
        uint64_t lane = ctx.state[i];
        for (int b = 0; b < 8; b++) out[i * 8 + b] = (uint8_t)(lane >> (8 * b));
    }
}

void keccak256(const uint8_t* input, size_t len, uint8_t output[32]) {
    keccak_ctx_t ctx;
    keccak_init(&ctx);
    keccak_update(&ctx, input, len);
    keccak_digest(&ctx, output);
}
