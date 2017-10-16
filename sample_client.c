#include "rpc_private.h"


static int sample_request(uint8_t opcode) {
    struct sd_req hdr = {0};
    struct sd_rsp rsp;
    int ret;
  
	hdr.opcode = opcode;
	hdr.proto_ver = SD_PROTO_VER;

    ret = rpc_send_socket_request("/run/edfssmb.sock", &hdr, &rsp, NULL);
    if(ret){
        return ret;
    }
    return rsp.result;
}

static void *test_loop(void *arg) {
	(void)arg;
    struct sd_req hdr;
    int n = 10;
	while (n --) {
        sample_request(RPC_OP_TYPE_FIX);
		sample_request(RPC_OP_TYPE_DYNAMIC);
	}
	return NULL;
}

int main () {
    pthread_t thread1;
	pthread_t thread2;
	pthread_t thread3;
	pthread_t thread4;
    pthread_create(&thread1, NULL, test_loop, NULL);
	pthread_create(&thread2, NULL, test_loop, NULL);
	pthread_create(&thread3, NULL, test_loop, NULL);
	pthread_create(&thread4, NULL, test_loop, NULL);
	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);
	pthread_join(thread3, NULL);
	pthread_join(thread4, NULL);
	return 0;
}

