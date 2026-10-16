// snappy.c - minimal snappy raw-format codec (see snappy/format_description.txt)
#include "snappy.h"
#include <string.h>

static size_t put_varint(uint8_t* out, size_t v) {
    size_t n = 0;
    while (v >= 0x80) {
        out[n++] = (uint8_t)(v | 0x80);
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

static size_t get_varint(const uint8_t* in, size_t in_len, size_t* v) {
    size_t n = 0, shift = 0;
    *v = 0;
    while (n < in_len && n < 10) {
        uint8_t b = in[n++];
        *v |= (size_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) return n;
        shift += 7;
    }
    return 0;
}

size_t snappy_max_compressed(size_t in_len) {
    return 10 + in_len + (in_len / 65536 + 1) * 5;
}

size_t snappy_compress(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap) {
    if (out_cap < snappy_max_compressed(in_len)) return 0;
    size_t o = put_varint(out, in_len);
    size_t i = 0;
    while (i < in_len) {
        size_t chunk = in_len - i;
        if (chunk > 65536) chunk = 65536;
        size_t n = chunk - 1;
        if (n < 60) {
            out[o++] = (uint8_t)(n << 2);
        } else if (n < 256) {
            out[o++] = 60 << 2;
            out[o++] = (uint8_t)n;
        } else {
            out[o++] = 61 << 2;
            out[o++] = (uint8_t)n;
            out[o++] = (uint8_t)(n >> 8);
        }
        memcpy(out + o, in + i, chunk);
        o += chunk;
        i += chunk;
    }
    return o;
}

size_t snappy_uncompressed_length(const uint8_t* in, size_t in_len) {
    size_t v;
    return get_varint(in, in_len, &v) ? v : 0;
}

size_t snappy_uncompress(const uint8_t* in, size_t in_len, uint8_t* out, size_t out_cap) {
    size_t expect;
    size_t i = get_varint(in, in_len, &expect);
    if (!i || expect > out_cap) return 0;

    size_t o = 0;
    while (i < in_len) {
        uint8_t tag = in[i++];
        size_t len, offset;
        switch (tag & 3) {
        case 0: { // literal
            len = (tag >> 2) + 1;
            if (len > 60) {
                size_t nb = len - 60;
                if (i + nb > in_len) return 0;
                len = 0;
                for (size_t k = 0; k < nb; k++) len |= (size_t)in[i + k] << (8 * k);
                len += 1;
                i += nb;
            }
            if (i + len > in_len || o + len > out_cap) return 0;
            memcpy(out + o, in + i, len);
            i += len;
            o += len;
            continue;
        }
        case 1: // copy with 1-byte offset
            if (i + 1 > in_len) return 0;
            len = ((tag >> 2) & 7) + 4;
            offset = ((size_t)(tag >> 5) << 8) | in[i];
            i += 1;
            break;
        case 2: // copy with 2-byte offset
            if (i + 2 > in_len) return 0;
            len = (tag >> 2) + 1;
            offset = in[i] | ((size_t)in[i + 1] << 8);
            i += 2;
            break;
        default: // copy with 4-byte offset
            if (i + 4 > in_len) return 0;
            len = (tag >> 2) + 1;
            offset = in[i] | ((size_t)in[i + 1] << 8) | ((size_t)in[i + 2] << 16) | ((size_t)in[i + 3] << 24);
            i += 4;
            break;
        }
        if (offset == 0 || offset > o || o + len > out_cap) return 0;
        // byte-wise copy: overlapping copies are intentional in snappy
        for (size_t k = 0; k < len; k++) out[o + k] = out[o - offset + k];
        o += len;
    }
    return o == expect ? o : 0;
}
