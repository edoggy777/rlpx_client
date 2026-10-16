#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>

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
        struct addrinfo hints, *res = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) {
            fprintf(stderr, "could not resolve host %s\n", host);
            close(sockfd);
            return -1;
        }
        addr.sin_addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr;
        freeaddrinfo(res);
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect() failed");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

ssize_t net_recv_exact(int sockfd, uint8_t* buf, size_t len, int timeout_ms) {
    size_t total = 0;
    while (total < len) {
        if (timeout_ms > 0) {
            struct pollfd pfd = { .fd = sockfd, .events = POLLIN };
            int pr = poll(&pfd, 1, timeout_ms);
            if (pr == 0) {
                fprintf(stderr, "DEBUG: recv timed out after %d ms\n", timeout_ms);
                return -1;
            }
            if (pr < 0) {
                if (errno == EINTR) continue;
                perror("poll() failed");
                return -1;
            }
        }
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

