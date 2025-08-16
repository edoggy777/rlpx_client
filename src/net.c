#include "net.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/time.h>

int net_connect(const char* host, uint16_t port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(sockfd);
        return -1;
    }
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

ssize_t net_send_all(int fd, const void* data, size_t len) {
    const uint8_t* ptr = (const uint8_t*)data;
    size_t sent = 0;
    
    while (sent < len) {
        ssize_t result = send(fd, ptr + sent, len - sent, 0);
        if (result <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        sent += result;
    }
    return sent;
}

ssize_t net_recv_exact(int sockfd, uint8_t* data, size_t len, int timeout_ms) {
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("DEBUG: setsockopt failed");
        return -1;
    }
    size_t got = 0;
    while (got < len) {
        ssize_t r = recv(sockfd, data + got, len - got, 0);
        if (r <= 0) {
            perror("DEBUG: recv failed");
            return -1;
        }
        got += r;
    }
    return got;
}

ssize_t net_recv_available(int fd, void* data, size_t max_len, int timeout_ms) {
    struct pollfd pfd = {fd, POLLIN, 0};
    
    // Wait for data to be available
    int poll_result = poll(&pfd, 1, timeout_ms);
    if (poll_result <= 0) {
        return -1; // timeout or error
    }
    
    // Receive whatever data is available
    ssize_t result = recv(fd, data, max_len, 0);
    return result; // Return actual bytes received (or -1 on error)
}

void net_close(int fd) {
    if (fd >= 0) close(fd);
}
