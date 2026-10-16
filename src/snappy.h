#ifndef SNAPPY_H
#define SNAPPY_H

#include <stdint.h>
#include <stddef.h>

// Minimal snappy (raw block format) for devp2p >= 5 message compression.
// Compression emits literal-only blocks (valid snappy, zero ratio) which is
// fine for a test/fuzz client; decompression handles the full format.

// Returns bytes written, 0 on error. out must hold snappy_max_compressed(in_len).
size_t snappy_max_compressed(size_t in_len);
size_t snappy_compress(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap);

// Returns decompressed length, 0 on error (or empty input).
size_t snappy_uncompressed_length(const uint8_t* in, size_t in_len);
size_t snappy_uncompress(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap);

#endif
