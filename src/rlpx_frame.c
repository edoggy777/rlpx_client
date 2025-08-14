// src/rlpx_frame.c
#include "rlpx_handshake.h"
#include "aes_mac.h"
#include "net.h"
#include <stdlib.h>
#include <string.h>

int rlpx_send_frame(rlpx_conn_t* conn, const uint8_t* payload, size_t len) {
    if (conn->state != RLPX_STATE_ESTABLISHED) return -1;
    
    // Allocate buffer for complete frame
    size_t frame_size = 3 + len + 16; // header + payload + MAC
    uint8_t* frame = malloc(frame_size);
    if (!frame) return -1;
    
    // 1. Create frame header (3 bytes: length in big-endian)
    frame[0] = (len >> 16) & 0xff;
    frame[1] = (len >> 8) & 0xff;  
    frame[2] = len & 0xff;
    
    // 2. AES-CTR encrypt payload
    if (aes_ctr_encrypt(&conn->secrets, payload, len, frame + 3) != 0) {
        free(frame);
        return -1;
    }
    
    // 3. Calculate MAC over header + encrypted payload
    uint8_t mac[16];
    if (calculate_frame_mac(&conn->secrets, frame, len + 3, mac) != 0) {
        free(frame);
        return -1;
    }
    memcpy(frame + len + 3, mac, 16);
    
    // 4. Send complete frame over TCP
    ssize_t sent = net_send_all(conn->sockfd, frame, frame_size);
    free(frame);
    
    return (sent == (ssize_t)frame_size) ? 0 : -1;
}

int rlpx_recv_frame(rlpx_conn_t* conn, uint8_t* payload, size_t* len) {
    if (conn->state != RLPX_STATE_ESTABLISHED) return -1;
    
    // 1. Read frame header (3 bytes)
    uint8_t header[3];
    if (net_recv_exact(conn->sockfd, header, 3, 5000) != 3) {
        return -1;
    }
    
    // Parse frame length from header
    size_t frame_len = ((uint32_t)header[0] << 16) | 
                       ((uint32_t)header[1] << 8) | 
                       header[2];
    
    if (frame_len > *len) {
        return -1; // Payload buffer too small
    }
    
    // 2. Read encrypted payload + MAC (frame_len + 16 bytes)
    uint8_t* frame_data = malloc(frame_len + 16);
    if (!frame_data) return -1;
    
    if (net_recv_exact(conn->sockfd, frame_data, frame_len + 16, 5000) != (ssize_t)(frame_len + 16)) {
        free(frame_data);
        return -1;
    }
    
    // 3. Verify MAC
    if (!verify_frame_mac(&conn->secrets, header, 3, frame_data, frame_len + 16)) {
        free(frame_data);
        return -1; // MAC verification failed
    }
    
    // 4. Decrypt payload (only the payload part, not the MAC)
    if (aes_ctr_decrypt(&conn->secrets, frame_data, frame_len, payload) != 0) {
        free(frame_data);
        return -1;
    }
    
    *len = frame_len;
    free(frame_data);
    return 0;
}

// Convenience function to send raw bytes (bypass normal framing for testing)
int rlpx_send_raw(rlpx_conn_t* conn, const uint8_t* data, size_t len) {
    if (conn->sockfd < 0) return -1;
    return net_send_all(conn->sockfd, data, len) == (ssize_t)len ? 0 : -1;
}
