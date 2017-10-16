/*
 * Copyright (C) 2009-2011 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <netinet/tcp.h>
#include <sys/types.h>    
#include <sys/socket.h>    
#include <sys/un.h> 

#include "rpc_private.h"

static struct system_info __sys;
struct system_info *sys = &__sys;

static bool serv_init = false;

static LIST_HEAD(listening_fd_list);

struct listening_fd {
	int fd;
	struct list_node list;
};

static struct request *alloc_local_request(void *data, int data_length)
{
	struct request *req;

	req = xzalloc(sizeof(struct request));
	if (data_length) {
		req->data_length = data_length;
		req->data = data;
	}

	req->local = true;

	refcount_set(&req->refcnt, 1);

	return req;
}

static void free_local_request(struct request *req)
{
	free(req);
}

static void submit_local_request(struct request *req)
{
	sd_mutex_lock(&sys->local_req_lock);
	list_add_tail(&req->request_list, &sys->local_req_queue);
	sd_mutex_unlock(&sys->local_req_lock);

	eventfd_xwrite(sys->local_req_efd, 1);
}

/*
 * Exec the request locally and synchronously.
 *
 * This function takes advantage of gateway's retry mechanism and can be only
 * called from worker thread.
 */
worker_fn int rpc_local_req(struct sd_req *rq, void *data)
{
	struct request *req;
	int ret;
	if(!serv_init){
		return SD_RES_NO_SERV;
	}

	req = alloc_local_request(data, rq->data_length);
	req->rq = *rq;
	req->local_req_efd = eventfd(0, 0);
	if (req->local_req_efd < 0) {
		sd_err("eventfd failed, %m");
		/* Fake the result to ask for retry */
		req->rp.result = SD_RES_NETWORK_ERROR;
		goto out;
	}

	submit_local_request(req);
	eventfd_xread(req->local_req_efd);
out:
	/* fill rq with response header as exec_req does */
	memcpy(rq, &req->rp, sizeof(req->rp));

	close(req->local_req_efd);
	ret = req->rp.result;
	free_local_request(req);

	return ret;
}

worker_fn int rpc_local_req_async(struct sd_req *rq, void *data,
    int (*local_callbak)(struct sd_rsp *rp,void *local_data),void *local_data)
{
    struct request *req;
    if(!serv_init){
        return SD_RES_NO_SERV;
    }

    req = alloc_local_request(data, rq->data_length);
    req->rq = *rq;
    req->local_callbak = local_callbak;
    req->local_data = local_data;
    submit_local_request(req);

    return SD_RES_SUCCESS;
}

const struct sd_op_template *get_sd_op(uint8_t opcode)
{	
	if (opcode >= sys->ops_count) {
		return NULL;
	}
	return sys->sd_ops + opcode;
}

static void destroy_client(struct client_info *ci)
{
	close(ci->conn.fd);
	free(ci);
}

static void free_request(struct request *req)
{
	refcount_dec(&req->ci->refcnt);
	free(req->data);
	free(req);
}

static void clear_client_info(struct client_info *ci)
{
	struct request *req;

	sd_debug("connection seems to be dead");

	list_for_each_entry(req, &ci->done_reqs, request_list) {
		list_del(&req->request_list);
		free_request(req);
	}

	unregister_event(ci->conn.fd);

	sd_debug("refcnt:%d, fd:%d, %s:%d", refcount_read(&ci->refcnt),
		 	 ci->conn.fd, ci->conn.ipstr, ci->conn.port);

	if (refcount_read(&ci->refcnt)) {
		return;
	}
	
	destroy_client(ci);
}

main_fn void put_request(struct request *req)
{
	struct client_info *ci = req->ci;

	if (refcount_dec(&req->refcnt) > 0)
		return;

	if (req->local){
        if(req->local_req_efd){
		    eventfd_xwrite(req->local_req_efd, 1);
        }else if(req->local_callbak){
            req->local_callbak(&req->rp,req->local_data);
            free_local_request(req);
        }
	}else {
		if (ci->conn.dead) {
			/*
			 * free_request should be called prior to
			 * clear_client_info because refcnt of ci will
			 * be decreased in free_request. Otherwise, ci
			 * cannot be freed in clear_client_info.
			 */
			free_request(req);
			clear_client_info(ci);
		} else {
			list_add_tail(&req->request_list, &ci->done_reqs);
			if (ci->tx_req == NULL){
				/* There is no request being sent. */
				if (conn_tx_on(&ci->conn)) {
					sd_err("switch on sending flag"
					       " failure, connection"
					       " maybe closed");
					/*
					 * should not free_request(req)
					 * here because it is already
					 * in done list
					 * clear_client_info will free
					 * it
					 */
					clear_client_info(ci);
				}
			}

		}
	}
}

struct request *alloc_request(struct client_info *ci, uint32_t data_length)
{
	struct request *req;

	req = zalloc(sizeof(struct request));
	if (!req)
		return NULL;

	if (data_length) {
		req->data_length = data_length;
		req->data = valloc(data_length);
		if (!req->data) {
			free(req);
			return NULL;
		}
	}

	req->ci = ci;
	refcount_inc(&ci->refcnt);
	refcount_set(&req->refcnt, 1);
	return req;
}

main_fn void get_request(struct request *req)
{
	refcount_inc(&req->refcnt);
}

void do_process_work(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	int ret = SD_RES_SUCCESS;

	if (req->op->process_work)
		ret = req->op->process_work(req);

	if (ret != SD_RES_SUCCESS) {
		sd_debug("failed: %x, %u, %d", req->rq.opcode,
			  req->rq.epoch, ret); 
	}

	req->rp.result = ret;
}

static void io_op_done(struct work *work)
{
	struct request *req = container_of(work, struct request, work);
	if(req->rp.result != SD_RES_SUCCESS){
        sd_debug("unhandled error:%x %d", req->rq.opcode, req->rp.result);
    }
	put_request(req);
}

static void queue_request(struct request *req)
{
	struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;

	/*
	 * Check the protocol version for all internal commands, and public
	 * commands that have it set.  We can't enforce it on all public
	 * ones as it isn't a mandatory part of the public protocol.
	 */
	if (hdr->opcode >= 0x80) {
        //noting
	} else if (hdr->proto_ver) {
		if (hdr->proto_ver > SD_PROTO_VER) {
			rsp->result = SD_RES_VER_MISMATCH;
			goto done;
		}
	}
	req->op = get_sd_op(hdr->opcode);
	if (NULL == req->op) {
		sd_err("invalid opcode %d", hdr->opcode);
		rsp->result = SD_RES_INVALID_PARMS;
		goto done;
	}
	
	req->work.fn = do_process_work;
	req->work.done = io_op_done;

	if (req->op->type < RPC_OP_MAX) {
		queue_work(sys->work_wqueue[req->op->type], &req->work);
	} else {
		sd_err("unknown operation %d", hdr->opcode);
		rsp->result = SD_RES_SYSTEM_ERROR;
		goto done;
	}

	return;
done:
	put_request(req);
}

static void rx_work(struct work *work)
{
	struct client_info *ci = container_of(work, struct client_info,
					      rx_work);
	int ret;
	struct connection *conn = &ci->conn;
	struct sd_req hdr;
	struct request *req;

    if(ci->rx_req!=NULL){
        sd_err("error rx_req");
		conn->dead = true;
		return;
    }

	ret = do_read(conn->fd, &hdr, sizeof(hdr), NULL, 0, UINT32_MAX);
	if (ret) {
		sd_debug("failed to read a header");
		conn->dead = true;
		return;
	}

	req = alloc_request(ci, hdr.data_length);
	if (!req) {
		sd_err("failed to allocate request");
		conn->dead = true;
		return;
	}

	ci->rx_req = req;

	/* use le_to_cpu */
	memcpy(&req->rq, &hdr, sizeof(req->rq));

	if (hdr.data_length&& hdr.flags & SD_FLAG_CMD_WRITE) {
		ret = do_read(conn->fd, req->data, hdr.data_length, NULL, 0,
			      UINT32_MAX);
		if (ret) {
			sd_err("failed to read data");
			conn->dead = true;
		}
	}
//	tracepoint(request, rx_work, conn->fd, work, req, hdr.opcode);
}

static void rx_main(struct work *work)
{
	struct client_info *ci = container_of(work, struct client_info,
					      rx_work);
	struct request *req = ci->rx_req;

	ci->rx_req = NULL;

	refcount_dec(&ci->refcnt);

	if (ci->conn.dead) {
		if (req)
			free_request(req);

		clear_client_info(ci);
		return;
	}

	if (conn_rx_on(&ci->conn))
		sd_err("switch on receiving flag failure, "
				"connection maybe closed");

//	tracepoint(request, rx_main, ci->conn.fd, work, req);
	queue_request(req);
}

static void tx_work(struct work *work)
{
	struct client_info *ci = container_of(work, struct client_info,
					      tx_work);
	int ret;
	struct connection *conn = &ci->conn;
	struct sd_rsp rsp;
	struct request *req = ci->tx_req;
	void *data = NULL;

	/* use cpu_to_le */
	memcpy(&rsp, &req->rp, sizeof(rsp));

	rsp.opcode = req->rq.opcode;
	rsp.id = req->rq.id;

	if (rsp.data_length)
		data = req->data;

	ret = send_req(conn->fd, (void *)&rsp, sizeof(struct sd_req), data, rsp.data_length,
		       NULL, 0, UINT32_MAX);
	if (ret != 0) {
		sd_err("failed to send a request");
		conn->dead = true;
	}
//	tracepoint(request, tx_work, conn->fd, work, req);
}

static void tx_main(struct work *work)
{
	struct client_info *ci = container_of(work, struct client_info,
					      tx_work);

//	tracepoint(request, tx_main, ci->conn.fd, work, ci->tx_req);
	
	refcount_dec(&ci->refcnt);


	sd_debug("%d, %s:%d",
		 ci->conn.fd,
		 ci->conn.ipstr,
		 ci->conn.port);

	free_request(ci->tx_req);
	ci->tx_req = NULL;

	if (ci->conn.dead) {
		clear_client_info(ci);
		return;
	}

	if (!list_empty(&ci->done_reqs)){
		if (conn_tx_on(&ci->conn))
			sd_err("switch on sending flag failure, "
					"connection maybe closed");
	}
}




static struct client_info *create_client(int fd)
{
	struct client_info *ci;
	struct sockaddr_storage from;
	socklen_t namesize = sizeof(from);

	ci = zalloc(sizeof(*ci));
	if (!ci)
		return NULL;

	if (getpeername(fd, (struct sockaddr *)&from, &namesize)) {
		free(ci);
		return NULL;
	}

	switch (from.ss_family) {
	case AF_INET:
		ci->conn.port = ntohs(((struct sockaddr_in *)&from)->sin_port);
		inet_ntop(AF_INET, &((struct sockaddr_in *)&from)->sin_addr,
				ci->conn.ipstr, sizeof(ci->conn.ipstr));
		break;
	case AF_INET6:
		ci->conn.port = ntohs(((struct sockaddr_in6 *)&from)->sin6_port);
		inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&from)->sin6_addr,
				ci->conn.ipstr, sizeof(ci->conn.ipstr));
		break;
	}
    
	ci->conn.fd = fd;
	ci->conn.events = EPOLLIN;
	refcount_set(&ci->refcnt, 0);
    ci->data = NULL;
    sd_debug("conn (%s:%d) connect to server",ci->conn.ipstr,ci->conn.port);
	INIT_LIST_HEAD(&ci->done_reqs);

//	tracepoint(request, create_client, fd);
	
	return ci;
}

static struct client_info *create_socket_client(int fd)
{
	struct client_info *ci;

	ci = zalloc(sizeof(*ci));
	if (!ci)
		return NULL;

    ci->conn.port = 0;
    snprintf(ci->conn.ipstr,sizeof(ci->conn.ipstr)-1,"local socket");

	ci->conn.fd = fd;
	ci->conn.events = EPOLLIN;
	refcount_set(&ci->refcnt, 0);
    ci->data = NULL;

	INIT_LIST_HEAD(&ci->done_reqs);

	return ci;
}

static void client_handler(int fd, int events, void *data)
{
	struct client_info *ci = (struct client_info *)data;

	sd_debug("%x, %d", events, ci->conn.dead);

	if (events & (EPOLLERR | EPOLLHUP))
		ci->conn.dead = true;
	/*
	 * Although dead is true, ci might not be freed immediately
	 * because of refcnt. Never mind, we will complete it later
	 * as long as dead is true.
	 */
	if (ci->conn.dead)
		return clear_client_info(ci);
	if (events & EPOLLIN) {
		if (conn_rx_off(&ci->conn) != 0) {
			sd_err("switch off receiving flag failure, "
					"connection maybe closed");
			return;
		}

		/*
		 * Increment refcnt so that the client_info isn't freed while
		 * rx_work uses it.
		 */
		refcount_inc(&ci->refcnt);
		ci->rx_work.fn = rx_work;
		ci->rx_work.done = rx_main;
		queue_work(sys->net_wqueue, &ci->rx_work);
	}

	if (events & EPOLLOUT) {
		if (conn_tx_off(&ci->conn) != 0) {
			sd_err("switch off sending flag failure, "
					"connection maybe closed");
			return;
		}
		
		assert(ci->tx_req == NULL);
		ci->tx_req = list_first_entry(&ci->done_reqs, struct request,
					      request_list);
		list_del(&ci->tx_req->request_list);
		/*
		 * Increment refcnt so that the client_info isn't freed while
		 * tx_work uses it.
		 */
		refcount_inc(&ci->refcnt);
		ci->tx_work.fn = tx_work;
		ci->tx_work.done = tx_main;
		queue_work(sys->net_wqueue, &ci->tx_work);
	}
}

static void listen_handler(int listen_fd, int events, void *data)
{
	struct sockaddr_storage from;
	socklen_t namesize;
	int fd, ret;
	struct client_info *ci;
	bool is_inet_socket = *(bool *)data;

	namesize = sizeof(from);
	fd = accept(listen_fd, (struct sockaddr *)&from, &namesize);
	if (fd < 0) {
		sd_err("failed to accept a new connection: %m");
		return;
	}

	if (is_inet_socket) {
		ret = set_nodelay(fd);
		if (ret) {
			close(fd);
			return;
		}
	}

	ci = create_client(fd);
	if (!ci) {
		close(fd);
		return;
	}

	ret = register_event(fd, client_handler, ci);
	if (ret) {
		destroy_client(ci);
		return;
	}

	sd_debug("accepted a new connection: %d", fd);
}

static void listen_socket_handler(int listen_fd, int events, void *data)
{
	struct sockaddr_un from;
	socklen_t namesize;
	int fd, ret;
	struct client_info *ci;
//	bool is_inet_socket = *(bool *)data;

	namesize = sizeof(from);
	fd = accept(listen_fd, (struct sockaddr *)&from, &namesize);
	if (fd < 0) {
		sd_err("failed to accept a new connection: %m");
		return;
	}
	
	ci = create_socket_client(fd);
	if (!ci) {
		close(fd);
		return;
	}

	ret = register_event(fd, client_handler, ci);
	if (ret) {
		destroy_client(ci);
		return;
	}

	sd_info("accepted a new connection: %d", fd);
}

static int create_listen_port_fn(int fd, void *data)
{
	struct listening_fd *new_fd;

	new_fd = xzalloc(sizeof(*new_fd));
	new_fd->fd = fd;
	list_add_tail(&new_fd->list, &listening_fd_list);

	return register_event(fd, listen_handler, data);
}

static int create_listen_socket_fn(int fd, void *data)
{
	struct listening_fd *new_fd;

	new_fd = xzalloc(sizeof(*new_fd));
	new_fd->fd = fd;
	list_add_tail(&new_fd->list, &listening_fd_list);

	return register_event(fd, listen_socket_handler, data);
}

void unregister_listening_fds(void)
{
	struct listening_fd *fd;

	list_for_each_entry(fd, &listening_fd_list, list) {
		sd_debug("unregistering fd: %d", fd->fd);
		unregister_event(fd->fd);
	}
}

static int create_listen_port(const char *bindaddr, int port)
{
	static bool is_inet_socket = true;

	return create_listen_ports(bindaddr, port, create_listen_port_fn,
				   &is_inet_socket);
}

static int create_listen_socket(const char *socket_path)
{
	static bool is_inet_socket = true;

	return create_unix_domain_socket(socket_path, create_listen_socket_fn,
				   &is_inet_socket);    
}

static void local_req_handler(int listen_fd, int events, void *data)
{
	struct request *req;
	LIST_HEAD(pending_list);

	if (events & EPOLLERR) {
		sd_err("request handler error");
	}
	eventfd_xread(listen_fd);

	sd_mutex_lock(&sys->local_req_lock);
	list_splice_init(&sys->local_req_queue, &pending_list);
	sd_mutex_unlock(&sys->local_req_lock);

	list_for_each_entry(req, &pending_list, request_list) {
		list_del(&req->request_list);
		queue_request(req);
	}
}
static int local_request_init(void)
{
	INIT_LIST_HEAD(&sys->local_req_queue);
	sd_init_mutex(&sys->local_req_lock);
	sys->local_req_efd = eventfd(0, EFD_NONBLOCK);
	if (sys->local_req_efd < 0) {
		panic("failed to init local req efd");
	}
	return register_event(sys->local_req_efd, local_req_handler, NULL);
}

int rpc_server_start(struct sd_op_template *ops, int ops_count, const char* addr, uint16_t port, const char* unixpath) {
    int ret = 0;
    sys->sd_ops = ops;
    sys->ops_count = ops_count;
    
	if (init_event(4096) < 0) {
		sd_err("failed to add epoll event ");
		return -1;
	}
    
	if (init_work_queue()) {
		return -1;
    }
    
    sys->net_wqueue = create_fixed_work_queue("WayFixed", 8);
   	if (!sys->net_wqueue) {
		sd_err("failed to create work queue");
		return -1;
	}

	sys->work_wqueue[RPC_OP_TYPE_FIX] = create_fixed_work_queue("WayFixed", 4);
	if (!sys->work_wqueue[RPC_OP_TYPE_FIX]) {
		sd_err("failed to create work queue");
		return -1;
	}

    sys->work_wqueue[RPC_OP_TYPE_DYNAMIC] = create_dynamic_work_queue("WayDynamic");
	if (!sys->work_wqueue[RPC_OP_TYPE_DYNAMIC]) {
		sd_err("failed to create work queue");
		return -1;
	}

    sys->work_wqueue[RPC_OP_TYPE_ORDERED] = create_ordered_work_queue("WayOrdered");
	if (!sys->work_wqueue[RPC_OP_TYPE_ORDERED]) {
		sd_err("failed to create work queue");
		return -1;
	}
	
    ret = local_request_init();
	if (ret) {
		return ret;
	}

    if (addr) {
        ret = create_listen_port(addr, port);
        if (ret) {
    		return ret;
    	}
    }
    
    if (unixpath) {
    	ret = create_listen_socket(unixpath);
    	if (ret) {
    		return ret;
    	}
    }
    
	serv_init = true;
    return ret;
}

