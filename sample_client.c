#include "rpc_private.h"

int main () {
    struct sd_req hdr = {0};
    struct sd_rsp rsp;
    int ret;
  
	hdr.opcode = RPC_OP_TYPE_FIX;
	hdr.proto_ver = SD_PROTO_VER;

    ret = rpc_send_request(&hdr, &rsp, NULL);
    if(ret){
        return ret;
    }
    return rsp.result;
}

