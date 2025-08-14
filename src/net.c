#include "net.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

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

ssize_t net_recv_exact(int fd, void* data, size_t len, int timeout_ms) {
    uint8_t* ptr = (uint8_t*)data;
    size_t received = 0;
    
    struct pollfd pfd = {fd, POLLIN, 0};
    
    while (received < len) {
        int poll_result = poll(&pfd, 1, timeout_ms);
        if (poll_result <= 0) return -1; // timeout or error
        
        ssize_t result = recv(fd, ptr + received, len - received, 0);
        if (result <= 0) return -1;
        received += result;
    }
    return received;
}

void net_close(int fd) {
    if (fd >= 0) close(fd);
}
