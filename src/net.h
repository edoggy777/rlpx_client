#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>

int net_connect(const char* host, uint16_t port);
ssize_t net_send_all(int sockfd, const uint8_t* buf, size_t len);
ssize_t net_recv_exact(int fd, uint8_t* data, size_t len, int timeout_ms);
ssize_t net_recv_available(int fd, void* data, size_t max_len, int timeout_ms);
void net_close(int fd);

#endif // NET_H
