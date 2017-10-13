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
#ifndef __RPC_PRIV_H__
#define __RPC_PRIV_H__

#include <inttypes.h>
#include <stdbool.h>
#include <urcu/uatomic.h>
#include <time.h>
#include <pthread.h>
#include <math.h>
#include <errno.h>
#include <poll.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/epoll.h>
#include <signal.h>

#include "rpc_proto.h"
#include "event.h"
#include "util.h"
#include "work.h"
#include "net.h"
#include "rbtree.h"

#define main_fn
#define worker_fn

struct client_info;

enum REQUST_STATUS {
	REQUEST_INIT,
	REQUEST_QUEUED,
	REQUEST_DONE,
	REQUEST_DROPPED
};


struct request_iocb {
	uint32_t count;
	int efd;
	int result;
};

enum sd_op_type {
	RPC_OP_TYPE_FIX = 1, /* FIX */
	RPC_OP_TYPE_DYNAMIC, /* DYNAMIC */
	RPC_OP_TYPE_ORDERED, /* ORDERED */
};

struct request;

struct sd_op_template {
	const char *name;
	enum sd_op_type type;

	/* process request even when cluster is not working */
	bool force;

	/*
	 * Indicates administrative operation to trace.
	 * If true is set, rx_main and tx_main log operations at info level.
	 */
	bool is_admin_op;

	/*
	 * process_work() will be called in a worker thread, and process_main()
	 * will be called in the main thread.
	 *
	 * If type is SD_OP_TYPE_CLUSTER, it is guaranteed that only one node
	 * processes a cluster operation at the same time.  We can use this for
	 * for example to implement distributed locking.  process_work()
	 * will be called on the local node, and process_main() will be called
	 * on every node.
	 *
	 * If type is SD_OP_TYPE_LOCAL, both process_work() and process_main()
	 * will be called on the local node.
	 *
	 * If type is SD_OP_TYPE_PEER, only process_work() will be called, and it
	 * will be called on the local node.
	 */
	int (*process_work)(struct request *req);
	int (*process_main)(const struct sd_req *req, struct sd_rsp *rsp,
			    void *data);
};


struct request {
	struct sd_req rq;
	struct sd_rsp rp;
	const struct sd_op_template *op;

	void *data;
	unsigned int data_length;

	struct client_info *ci;
	struct list_node request_list;
	struct list_node pending_list;

	refcnt_t refcnt;
	bool local;
	int local_req_efd;
    int (*local_callbak)(struct sd_rsp *rp,void *local_data);
    void *local_data;
	struct work work;
	enum REQUST_STATUS status;
	bool stat; /* true if this request is during stat */
};


struct system_info {
	const char *cdrv_option;
	
	int local_req_efd;

	struct sd_mutex local_req_lock;
	struct list_head local_req_queue;
	struct list_head req_wait_queue;
	int nr_outstanding_reqs;


	struct sd_op_template *sd_ops;
	uint8_t ops_count;
    
    struct work_queue *net_wqueue;
	struct work_queue *fixed_work;
	struct work_queue *dynamic_work;
	struct work_queue *ordered_work;

	/* upgrade data layout before starting service if necessary*/
	bool upgrade;
};

struct sdrequest_cache {
	struct rb_root root;
	struct sd_rw_lock lock;
	int count;
};

struct sd_client {
	uint32_t seq_num;
	pthread_t request_thread;
	int request_fd;
	struct list_head request_list;
	struct list_head inflight_list;
	struct list_head blocking_list;
	uatomic_bool stop_request_handler;
	struct sd_mutex request_lock;

	struct connection conn;

	uint32_t write_retry;
	uint32_t read_retry;
	uint32_t connect_retry;
	uint32_t reconnect_count;
    bool new_conn;

	struct sdrequest_cache sdreq_cache;
};

struct sd_request {
	struct rb_node rb;
	struct sd_client *cluster;
	struct list_node list;
	struct sd_req *hdr;
	void *data;
	size_t length;
	off_t offset;
	uint8_t opcode;
	int efd;
	int ret;
	pthread_t tid;
	uint32_t seq_num;
	refcnt_t ref_count;
};

struct reconnect_entry{
	struct sd_client *ci;
	struct timer t;
};

int rpc_server_start(struct sd_op_template *ops, int ops_count);
int rpc_server_socket_start(const char *socket_path,
                    int wq_net_threads, int wq_io_threads,int wq_flush_threads,int wq_load_threads,int wq_meta_threads, 
					struct sd_op_template *ops,int ops_count );
int rpc_server_stop(void);


void rpc_server_ci_attach(struct client_info *ci, void *data);
void rpc_server_ci_deach(struct client_info *ci);
void *rpc_server_ci_get(struct client_info *ci);
void rpc_server_regist_disconnect(void (*cb)(struct client_info *));



struct request_iocb *rpc_local_req_init(void);
int rpc_local_req_wait(struct request_iocb *iocb);
int rpc_local_req_async(struct sd_req *rq, void *data,
    int (*local_callbak)(struct sd_rsp *rp,void *local_data),void *local_data);


int rpc_server_local_req(struct sd_req *rq, void *data);


struct sd_client *rpc_client_connect(char *host);
struct sd_client *rpc_client_connect_socket(const char *socket_path);
int rpc_client_disconnect(struct sd_client *c);
int rpc_client_is_new_session(struct sd_client *c);
void rpc_client_reset_new_session(struct sd_client *c);
void rpc_client_retry(struct sd_client *c,int connect_retry,int read_retry,int write_retry);
int rpc_client_run_req(struct sd_client *c, struct sd_req *hdr, void *data);

int rpc_send_request(struct sd_req * req, struct sd_rsp *rsp, uint8_t *buff);

#endif

