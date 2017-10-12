#include "event.h"
#include "rpc_private.h"
#include <errno.h>

#define SAMPLE_OP_FIX           0x01
#define SAMPLE_OP_DYNAMIC       0x02
#define SAMPLE_OP_ORDERED       0x03

static int do_fix_op(struct request *req){
	struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	sd_notice("do fix thread begin tid(%d)", gettid());
    sleep(1);
    sd_notice("do fix thread end %d", gettid());
	return 0;
}

static int do_dynamic_op(struct request *req){
	struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	sd_notice("do dynamic thread begin tid(%d)", gettid());
    sleep(1);
    sd_notice("do dynamic thread end %d", gettid());
	return 0;
}

static int do_ordered_op(struct request *req){
	struct sd_req *hdr = &req->rq;
	struct sd_rsp *rsp = &req->rp;
	sd_notice("do ordered thread begin tid(%d)", gettid());
    sleep(1);
    sd_notice("do ordered thread end %d", gettid());
	return 0;
}

static struct sd_op_template serv_ops[] = {
	[SAMPLE_OP_FIX] = {
		.name = "SAMPLE_OP_FIX",
		.type = RPC_OP_TYPE_FIX,
		.is_admin_op = false,
		.process_work = do_fix_op,
		.process_main = NULL,
	},
	/* cluster operations */
	[SAMPLE_OP_DYNAMIC] = {
		.name = "SAMPLE_OP_DYNAMIC",
		.type = RPC_OP_TYPE_DYNAMIC,
		.is_admin_op = false,
		.process_work = do_dynamic_op,
		.process_main = NULL,
	},
	[SAMPLE_OP_ORDERED] = {
		.name = "SAMPLE_OP_ORDERED",
		.type = RPC_OP_TYPE_ORDERED,
		.is_admin_op = false,
		.process_work = do_ordered_op,
		.process_main = NULL,
	},
};

static void *work_loop(void *arg) {
	(void)arg;
	while (true) {
		event_loop(-1);
	}
	return NULL;
}

static void *test_loop(void *arg) {
	(void)arg;
    struct sd_req hdr;
    int n = 50;
	while (n --) {
        hdr.opcode = SAMPLE_OP_FIX;
        hdr.proto_ver = SD_PROTO_VER;
        rpc_local_req_async(&hdr, NULL, NULL, NULL);
        hdr.opcode = SAMPLE_OP_DYNAMIC;
        hdr.proto_ver = SD_PROTO_VER;
        rpc_local_req_async(&hdr, NULL, NULL, NULL);
        hdr.opcode = SAMPLE_OP_ORDERED;
        hdr.proto_ver = SD_PROTO_VER;
        rpc_local_req_async(&hdr, NULL, NULL, NULL);
	}
	return NULL;
}

int main() {  
    pthread_t thread;
    pthread_t thread1;
    int ret = 0;
    rpc_server_start(serv_ops, sizeof(serv_ops));
    pthread_create(&thread, NULL, work_loop, NULL);
    sleep(1);
    pthread_create(&thread1, NULL, test_loop, NULL);
    pthread_join(thread, NULL);
    return 0;
}
