#pragma once
// Shrinks the accept queue of a listening TCP socket that a library created for us
// (Arduino's WebServer listens with a backlog of 4 and doesn't expose the socket).
//
// lwIP allocates a netconn for every connection waiting in that queue, and netconns
// share the 16-socket limit (MEMP_NUM_NETCONN = CONFIG_LWIP_MAX_SOCKETS): a browser
// opening several connections to the idle-priority web task could take 6 and starve
// a DoT reconnect or the blocklist download (audit 2026-11; ARCHITECTURE.md §11).
// lwIP lets listen() on a listening socket update its backlog (TCP_LISTEN_BACKLOG = 1
// in the prebuilt lwipopts.h).

#include <lwip/sockets.h>

#include <cstdint>

namespace platform {

// Returns true if a listening TCP socket on `port` was found and updated.
inline bool setListenBacklog(uint16_t port, int backlog) {
  for (int fd = LWIP_SOCKET_OFFSET; fd < LWIP_SOCKET_OFFSET + CONFIG_LWIP_MAX_SOCKETS; fd++) {
    int listening = 0;
    socklen_t len = sizeof(listening);
    if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &len) != 0 || !listening) continue;
    struct sockaddr_storage addr;
    socklen_t alen = sizeof(addr);
    if (getsockname(fd, reinterpret_cast<struct sockaddr*>(&addr), &alen) != 0) continue;
    uint16_t p = 0;
    if (addr.ss_family == AF_INET) p = ntohs(reinterpret_cast<struct sockaddr_in*>(&addr)->sin_port);
#if LWIP_IPV6
    if (addr.ss_family == AF_INET6) p = ntohs(reinterpret_cast<struct sockaddr_in6*>(&addr)->sin6_port);
#endif
    if (p == port) return listen(fd, backlog) == 0;
  }
  return false;
}

}  // namespace platform
