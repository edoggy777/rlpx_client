// src/keccak.c
// Minimal Keccak-256 implementation for RLPx
// Based on the Keccak reference implementation

#include "keccak.h"
#include <string.h>
#include <stdint.h>

#define KECCAK_ROUNDS 24

// Keccak round constants
static const uint64_t keccak_round_constants[KECCAK_ROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL,
    0x800000008000000aULL, 0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL, 0x0000000000008082ULL,
    0x8000000000008003ULL, 0x8000000080008080ULL, 0x8000000080000001ULL
};

// Rotation offsets
static const unsigned int keccak_rho_offsets[25] = {
     0,  1, 62, 28, 27, 36, 44,  6, 55, 20,  3, 10, 43, 25, 39, 41, 45, 15,
    21,  8, 18,  2, 61, 56, 14
};

// Left rotation
static inline uint64_t rotl64(uint64_t x, unsigned int n) {
    return (x << n) | (x >> (64 - n));
}

// Keccak-f[1600] permutation
static void keccak_f1600(uint64_t state[25]) {
    uint64_t C[5], D[5], B[25];
    
    for (int round = 0; round < KECCAK_ROUNDS; round++) {
        // Theta step
        for (int x = 0; x < 5; x++) {
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
        }
        
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                state[y * 5 + x] ^= D[x];
            }
        }
        
        // Rho and Pi steps
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                B[y * 5 + ((2 * x + 3 * y) % 5)] = rotl64(state[y * 5 + x], keccak_rho_offsets[y * 5 + x]);
            }
        }
        
        // Chi step
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                state[y * 5 + x] = B[y * 5 + x] ^ ((~B[y * 5 + ((x + 1) % 5)]) & B[y * 5 + ((x + 2) % 5)]);
            }
        }
        
        // Iota step
        state[0] ^= keccak_round_constants[round];
    }
}

// Main Keccak-256 function
void keccak256(const uint8_t* input, size_t len, uint8_t output[32]) {
    uint64_t state[25] = {0};
    uint8_t* state_bytes = (uint8_t*)state;
    
    const size_t rate = 136; // 1600 - 2*256 = 1088 bits = 136 bytes
    size_t offset = 0;
    
    // Absorbing phase
    while (len >= rate) {
        for (size_t i = 0; i < rate; i++) {
            state_bytes[i] ^= input[offset + i];
        }
        keccak_f1600(state);
        offset += rate;
        len -= rate;
    }
    
    // Padding and final block
    for (size_t i = 0; i < len; i++) {
        state_bytes[i] ^= input[offset + i];
    }
    
    // Keccak padding: append 0x01
    state_bytes[len] ^= 0x01;
    
    // Append 0x80 at the end of the rate
    state_bytes[rate - 1] ^= 0x80;
    
    // Final permutation
    keccak_f1600(state);
    
    // Squeezing phase - extract 256 bits (32 bytes)
    memcpy(output, state_bytes, 32);
}
