#ifndef __SOCKET_CACHE_H_
#define __SOCKET_CACHE_H_

#include "work.h"


/* sockfd_cache */
struct sockfd {
	int fd;
	int idx;
};

struct node_id {
	uint8_t addr[16];
	uint16_t port;
    uint16_t is_socket;
    uint8_t unixpath[256];
};

struct sockfd *sockfd_cache_get(const struct node_id *nid);
void sockfd_cache_put(const struct node_id *nid, struct sockfd *sfd);
void sockfd_cache_del_node(const struct node_id *nid);
void sockfd_cache_del(const struct node_id *nid, struct sockfd *sfd);
void sockfd_cache_add(const struct node_id *nid);

int sockfd_init(void);

#endif
