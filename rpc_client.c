#include "util.h"
#include "event.h"
#include "rpc_private.h"
#include "sockfd_cache.h"

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/poll.h> 

#define FAST_RECONNECT 10

static bool eofs_need_retry(uint32_t epoch)
{
    return true;
}


static int rpc_wait_request(const struct node_id *nid, struct sd_rsp *rsp, struct sockfd *sfd, uint8_t *buff)
{
	int err_ret = 0, pollret, repeat = MAX_RETRY_COUNT;
	struct pollfd pfds[1];
	
again:
	pfds[0].fd = sfd->fd;
	pfds[0].events = POLLIN;
	pollret = poll(pfds, 1, 1000 * POLL_TIMEOUT);
	if (pollret < 0) {
		if (errno == EINTR) {
			goto again;
        }
		panic("%m");
	} else if (pollret == 0) {
		if (repeat) {
			repeat--;
			sd_notice("poll timeout , disks of some nodes or network is busy. Going to poll-wait again");
			goto again;
		}
		sockfd_cache_del(nid, sfd);
        sd_notice("%s:%d repeat(%d)",nid->addr,nid->port,repeat);
		return EIO;
	}

	if (pfds[0].revents & POLLIN){
		int re = pfds[0].revents;
		if (re & (POLLERR | POLLHUP | POLLNVAL)) {
			err_ret = EIO;
			sockfd_cache_del(nid, sfd);
            sd_err("poll error remote node might have gone away");
			goto out;
		}
		if (do_read(pfds[0].fd, rsp, sizeof(*rsp), eofs_need_retry,
			    0, MAX_RETRY_COUNT)) {
			sd_err("remote node might have gone away");
			err_ret = EIO;
			sockfd_cache_del(nid, sfd);
			goto out;
		}

		if (rsp->data_length) {
			if (do_read(pfds[0].fd, buff, rsp->data_length,
				    eofs_need_retry, 0,
				    MAX_RETRY_COUNT)) {
				sd_err("remote node might have gone away");
				err_ret = EIO;
				sockfd_cache_del(nid, sfd);
				goto out;
			}
		}
		sockfd_cache_put(nid, sfd);
	}
out:
	return err_ret;
}

int __rpc_send_request(struct node_id *nid, struct sd_req * req, struct sd_rsp *rsp, uint8_t *buff)
{
    int ret;
	unsigned wlen = 0;
	uint8_t *data = NULL;
	struct sockfd *sfd;
    uint32_t epoch = 0;

	sfd = sockfd_cache_get(nid);
	if (!sfd) {
        if (!nid->is_socket) {
            sd_err("get sock fail, addr(%s:%d)",nid->addr, nid->port);
        } else {
            sd_err("get sock fail, unixpath(%s)",nid->unixpath);
        }
		return -1;
	}

    ret = send_req(sfd->fd, (void *)req, sizeof(struct sd_req), data, wlen, eofs_need_retry, 0, MAX_RETRY_COUNT);
	if (ret) {
        sockfd_cache_del(nid, sfd);
		return ret;
	}
    
	ret = rpc_wait_request(nid, rsp, sfd, buff);
	if (ret) {
		return ret;
    }

    return 0;
}

int rpc_send_request(const char *addr, uint16_t port, struct sd_req * req, struct sd_rsp *rsp, uint8_t *buff)
{
	struct node_id nid;
    
    memset(&nid, 0, sizeof(nid));
    memcpy(nid.addr, addr, strlen(addr));
    nid.port = port;

	return __rpc_send_request(&nid, req, rsp, buff);
}

int rpc_send_socket_request(const char* unixpath, struct sd_req * req, struct sd_rsp *rsp, uint8_t *buff)
{
	struct node_id nid;
    
    memset(&nid, 0, sizeof(nid));
    nid.is_socket = 1;
    memcpy(nid.unixpath, unixpath, strlen(unixpath));

	return __rpc_send_request(&nid, req, rsp, buff);

}

