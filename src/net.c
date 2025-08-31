#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

int net_connect(const char* host, uint16_t port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() failed");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "inet_pton() failed for %s\n", host);
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect() failed");
        close(sockfd);
        return -1;
    }

    printf("DEBUG: connected to %s:%u (sockfd=%d)\n", host, port, sockfd);
    return sockfd;
}

ssize_t net_recv_exact(int sockfd, uint8_t* buf, size_t len, int timeout_ms) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(sockfd, buf + total, len - total, 0);
        if (n < 0) {
            perror("recv() failed");
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "DEBUG: recv() returned 0 (peer closed connection)\n");
            return -1;
        }
        total += n;
    }
    return total;
}


ssize_t net_send_all(int sockfd, const uint8_t* buf, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = send(sockfd, buf + total_sent, len - total_sent, 0);
        if (sent <= 0) {
            if (sent < 0 && errno == EINTR) continue; // interrupted, retry
            return -1; // error or closed connection
        }
        total_sent += sent;
    }
    return total_sent;
}

void net_close(int sockfd) {
    if (sockfd >= 0) close(sockfd);
}

