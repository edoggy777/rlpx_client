#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int net_connect(const char* host, uint16_t port);
ssize_t net_send_all(int fd, const void* data, size_t len);
ssize_t net_recv_exact(int fd, void* data, size_t len, int timeout_ms);
void net_close(int fd);

#endif // NET_H
